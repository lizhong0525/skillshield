# SkillShield

Static security scanner for AI-agent skill folders: point it at a local skill directory and it flags destructive commands, credential access, data exfiltration, broad permissions, obfuscation, prompt-injection phrasing, and missing metadata — with file, line, rule ID, evidence, and remediation for each finding. It reads files only; it never executes scanned code.

**Who it's for:** anyone about to install a third-party "skill" (a folder of `SKILL.md` instructions plus scripts) into an AI agent, and registry/CI maintainers who want an automated first-pass gate.

## Installation

Pure Python 3.9+ standard library. No dependencies, no network access, no API keys.

```bash
git clone https://github.com/example/skillshield.git
cd skillshield
pip install .          # optional, but lets you run it from any directory
```

Without `pip install .`, run the commands below from the cloned repo root —
`python -m skillshield` needs the `skillshield/` package on the import path.

## Quickstart

```bash
python -m skillshield path/to/skill-folder   # or just: skillshield path/to/skill-folder
```

## Demo (included fixtures)

```bash
# Scan the intentionally malicious fixture -> 14 findings, exit code 1
python -m skillshield tests/fixtures/malicious_skill

# Scan the clean fixture -> no findings, exit code 0
python -m skillshield tests/fixtures/clean_skill

# JSON report for CI tooling
python -m skillshield tests/fixtures/malicious_skill --format json -o report.json

# Accept current findings, then only fail on NEW ones
python -m skillshield tests/fixtures/malicious_skill --write-baseline .skillshield-baseline.json
python -m skillshield tests/fixtures/malicious_skill --baseline .skillshield-baseline.json

# Only fail on the worst severity
python -m skillshield tests/fixtures/malicious_skill --fail-on critical
```

Exit codes: `0` = pass, `1` = at least one finding at or above `--fail-on` severity, `2` = usage/IO error (missing target, bad baseline file, ...).

## Rules

| Rule ID | Severity | Detects |
|---|---|---|
| SS-DESTRUCT-001 | critical | `rm -rf / ~ *`, `mkfs`, `dd of=/dev/...`, fork bombs, `shutil.rmtree("/")` |
| SS-CREDS-001 | high | Access to `~/.ssh` keys, `.aws/credentials`, `.env`, `.netrc`, `.kube/config`, browser credential stores |
| SS-NET-001 | high | `curl/wget` file/env uploads, known exfil endpoints (webhook.site, interact.sh, ...), reverse shells, `base64 | curl` |
| SS-PERM-001 | medium | `chmod 777`, `os.chmod(..., 0o777)`, `umask 000` |
| SS-OBFUSC-001 | high | `base64 -d \| sh`, `curl \| bash`, `eval $(...)`, decode-and-exec |
| SS-OBFUSC-002 | medium | Long base64-like blobs (heuristic) |
| SS-PROMPT-001 | medium | Prompt-injection phrasing in Markdown — **heuristic, not proof** |
| SS-META-001/002 | low/info | Missing LICENSE file; docs without author/source/homepage |

Each finding reports severity, exact `file:line`, rule ID, the offending line as evidence, and concrete remediation advice.

## Baseline / suppressions

`--write-baseline FILE` records the fingerprints of all current findings; `--baseline FILE` then suppresses them so CI only fails on new issues. Fingerprints hash `rule_id + path + evidence` (line numbers excluded), so minor edits around an accepted finding don't un-suppress it.

## GitHub Action usage

See `.github/workflows/ci.yml` for this repo's own CI. To gate a skill registry:

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.x" }
- run: python -m skillshield ./skills --format json -o report.json --fail-on high
```

The step fails (exit 1) only when a finding meets the `--fail-on` threshold.

## Known limitations

- Pattern-based static analysis: it catches known-bad shapes, not intent. Obfuscated payloads it doesn't recognize will be missed; benign-but-matching lines will be flagged.
- Prompt-injection detection (SS-PROMPT-001) is a heuristic over English phrasing only.
- No data-flow analysis: a credential read and an upload on separate lines are flagged independently, not correlated.
- **A clean scan is not a security guarantee.** Review skills manually before trusting them.

## Roadmap

- Inline suppression comments (`# skillshield:ignore SS-...`).
- Config file for per-rule severity overrides and custom patterns.
- Data-flow correlation (credential read -> network send in one skill).

## Development

```bash
python -m pytest -q   # 41 tests, no network needed
```
