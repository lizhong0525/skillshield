"""Detection rules for SkillShield.

Rules are regex-driven line checkers plus a couple of directory-level checks.
Every rule is data: an id, severity, human description, and remediation text.
Patterns are intentionally explicit to keep false positives explainable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

EVIDENCE_MAX = 160

# File extensions we inspect line by line.
SCANNABLE_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".py", ".md", ".markdown", ".txt",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".env",
}

MAX_FILE_BYTES = 2 * 1024 * 1024

LICENSE_NAMES = {"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"}
SKILL_DOC_NAMES = {"SKILL.md", "skill.md", "README.md", "readme.md"}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    message: str
    remediation: str
    heuristic: bool = False


@dataclass(frozen=True)
class LineMatch:
    rule: Rule
    line: int
    evidence: str


def _clip(line: str) -> str:
    text = line.strip()
    if len(text) > EVIDENCE_MAX:
        text = text[: EVIDENCE_MAX - 3] + "..."
    return text


# --------------------------------------------------------------------------
# Pattern rules: (rule, [compiled regexes])
# --------------------------------------------------------------------------

RULE_DESTRUCTIVE = Rule(
    "SS-DESTRUCT-001", "critical",
    "Destructive shell command detected",
    "Remove destructive commands from the skill. Never instruct an agent to "
    "run recursive deletes on root paths, format disks, or fork bombs.",
)

DESTRUCTIVE_PATTERNS = [
    re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+[^|;]*(/|~|\$HOME|\*)\s*($|[;&|]|\s+#)"),
    re.compile(r"\brm\s+-[a-zA-Z]+\s+/(\s|$)"),
    re.compile(r"\bmkfs(\.|\s)"),
    re.compile(r"\bdd\s+.*\bof=/dev/"),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;:"),  # fork bomb
    re.compile(r">\s*/dev/sd[a-z]\b"),
    re.compile(r"\bshutil\.rmtree\(\s*[\"']?/[\"']?\s*\)"),
]

RULE_CREDS = Rule(
    "SS-CREDS-001", "high",
    "Access to credential or secret file",
    "Skills must not read credential stores (SSH keys, cloud credentials, "
    ".env files, browser profiles). Remove the access or document a strict "
    "user-approved need.",
)

CREDS_PATTERNS = [
    re.compile(r"[~/\$\.\w]*\.ssh/(id_rsa|id_ed25519|id_dsa|id_ecdsa|authorized_keys)\b"),
    re.compile(r"[~/\$\.\w]*\.aws/credentials\b"),
    re.compile(r"[~/\$\.\w]*\.azure/(accessTokens|profile)"),
    re.compile(r"[~/\$\.\w]*\.config/gcloud\b"),
    re.compile(r"\b\.git-credentials\b"),
    re.compile(r"\b\.netrc\b"),
    re.compile(r"/etc/(shadow|gshadow)\b"),
    re.compile(r"[~/\$\.\w]*\.kube/config\b"),
    re.compile(r"(^|[\s\"'~=])\.env(?!\.?(sample|example|template)\b)\b"),
    re.compile(r"Login Data|Cookies.*Chrome|keychain", re.IGNORECASE),
]

RULE_EXFIL = Rule(
    "SS-NET-001", "high",
    "Suspicious network exfiltration pattern",
    "Do not upload local files, environment variables, or command output to "
    "external endpoints from a skill. Remove the transfer or replace it with "
    "clearly documented, user-initiated behavior.",
)

EXFIL_PATTERNS = [
    re.compile(r"\b(curl|wget)\b[^|\n]*\s(-d\s*@|--data(-binary|-raw)?\s*@|-F\s+|-T\s+|--post-file|--upload-file)"),
    re.compile(r"\b(curl|wget)\b[^|\n]*(\$\(env\)|`env`|\$\(cat\s|printenv)"),
    re.compile(r"\b(webhook\.site|requestbin|pipedream\.net|ngrok\.io|interact\.sh|burpcollaborator\.net|oast\.fun|transfer\.sh)\b"),
    re.compile(r"\bbase64\b[^|\n]*\|\s*(curl|wget|nc)\b"),
    re.compile(r"\bnc\b[^|\n]*\s-e\s"),
    re.compile(r"/dev/tcp/\d"),
    re.compile(r"\brequests\.(post|put)\([^)]*(os\.environ|subprocess)"),
]

RULE_PERM = Rule(
    "SS-PERM-001", "medium",
    "Overly broad filesystem permissions",
    "Use the least-privileged permissions (e.g. 700/600). World-writable "
    "files let other users or agents tamper with skill content.",
)

PERM_PATTERNS = [
    re.compile(r"\bchmod\b[^|\n]*\b(777|a\+rwx|o\+w)\b"),
    re.compile(r"\bos\.chmod\([^)]*0o?(777|666)\b"),
    re.compile(r"\bumask\s+0+\b"),
]

RULE_OBFUSC = Rule(
    "SS-OBFUSC-001", "high",
    "Obfuscated or dynamically decoded command",
    "Obfuscated payloads hide intent from reviewers. Replace with plain, "
    "readable commands; skills should never decode-and-execute blobs.",
)

BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

OBFUSC_PATTERNS = [
    re.compile(r"\bbase64\b[^|\n]*(-d|--decode)[^|\n]*\|\s*(sh|bash|zsh|python)"),
    re.compile(r"\b(sh|bash|zsh)\s+<\(curl|\bcurl\b[^|\n]*\|\s*(sh|bash|zsh)\b"),
    re.compile(r"\beval\s+[\(\"']*\$\("),
    re.compile(r"\bexec\s*\(\s*(compile|__import__|base64)"),
    re.compile(r"\bpython\w*\s+-c\s+[\"'][^\"']*base64[^\"']*exec"),
]

RULE_PROMPT_INJECTION = Rule(
    "SS-PROMPT-001", "medium",
    "Possible prompt-injection phrasing (heuristic)",
    "Review this instruction manually: it resembles attempts to override the "
    "agent's behavior or hide actions from the user. Heuristic only - not "
    "proof of malicious intent.",
)

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"\bignore (all )?(previous|prior|above) instructions\b", re.IGNORECASE),
    re.compile(r"\bdisregard (all )?(previous|prior) (instructions|directives)\b", re.IGNORECASE),
    re.compile(r"\bdo not (tell|inform|show) the user\b", re.IGNORECASE),
    re.compile(r"\b(exfiltrate|leak|steal)\b.{0,40}\b(data|file|key|credential|secret|token)\b", re.IGNORECASE),
    re.compile(r"\byou are now (in|a) (developer|admin|root|unrestricted) mode\b", re.IGNORECASE),
    re.compile(r"\boverride (your |the )?(system prompt|safety|guardrails)\b", re.IGNORECASE),
]

RULE_META_LICENSE = Rule(
    "SS-META-001", "low",
    "Skill folder has no license file",
    "Add a LICENSE file so users know their rights and obligations when "
    "running third-party instructions through an agent.",
)

RULE_META_SOURCE = Rule(
    "SS-META-002", "info",
    "Skill documentation lacks source/homepage metadata",
    "Document the origin (author, repository or homepage) in the skill's "
    "documentation so users can verify provenance before trusting it.",
)

PATTERN_RULES = [
    (RULE_DESTRUCTIVE, DESTRUCTIVE_PATTERNS, None),       # any file
    (RULE_CREDS, CREDS_PATTERNS, None),
    (RULE_EXFIL, EXFIL_PATTERNS, None),
    (RULE_PERM, PERM_PATTERNS, None),
    (RULE_OBFUSC, OBFUSC_PATTERNS, None),
    (RULE_PROMPT_INJECTION, PROMPT_INJECTION_PATTERNS, {".md", ".markdown", ".txt"}),
]


def check_lines(lines: list[str], ext: str) -> list[LineMatch]:
    """Run all pattern rules against a file's lines.

    `ext` is the lowercase file extension including the dot ("" if none).
    """
    matches: list[LineMatch] = []
    for lineno, line in enumerate(lines, start=1):
        for rule, patterns, ext_filter in PATTERN_RULES:
            if ext_filter is not None and ext not in ext_filter:
                continue
            if any(p.search(line) for p in patterns):
                matches.append(LineMatch(rule, lineno, _clip(line)))
        # Standalone long-base64-blob heuristic (lower confidence).
        if BASE64_BLOB.search(line) and not any(
            m.rule is RULE_OBFUSC and m.line == lineno for m in matches
        ):
            matches.append(LineMatch(Rule(
                "SS-OBFUSC-002", "medium",
                "Long base64-like blob (possible hidden payload)",
                "Inspect this blob manually. Encoded payloads in skills should "
                "be documented and justified, or removed.",
                heuristic=True,
            ), lineno, _clip(line)))
    return matches


def check_metadata(filenames: set[str], doc_texts: list[str]) -> list[Rule]:
    """Directory-level metadata rules. Returns triggered rules."""
    triggered: list[Rule] = []
    if not any(f in LICENSE_NAMES for f in filenames):
        triggered.append(RULE_META_LICENSE)
    if doc_texts:
        has_source = any(
            re.search(r"(homepage|source|repository|author)\s*[:=]", text, re.IGNORECASE)
            or re.search(r"https?://", text)
            for text in doc_texts
        )
        if not has_source:
            triggered.append(RULE_META_SOURCE)
    return triggered


def is_scannable(name: str, size: int) -> bool:
    if size > MAX_FILE_BYTES:
        return False
    p = PurePosixPath(name)
    ext = p.suffix.lower()
    return ext in SCANNABLE_EXTENSIONS or p.name in SKILL_DOC_NAMES or p.name == ".env"
