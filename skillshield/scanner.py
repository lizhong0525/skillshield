"""Directory walking and rule application. Never executes scanned code."""

from __future__ import annotations

import os
from pathlib import Path

from .models import Finding, ScanResult
from . import rules

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}


def _read_text(path: Path) -> str | None:
    """Read a file as UTF-8 text; return None for binary/undecodable files."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:  # binary heuristic
        return None
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return None


def scan_directory(root: str | os.PathLike) -> ScanResult:
    """Scan a skill folder and return a ScanResult.

    Raises FileNotFoundError / NotADirectoryError for invalid roots.
    """
    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"scan target does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"scan target is not a directory: {root_path}")

    result = ScanResult(root=str(root_path))
    filenames: set[str] = set()
    doc_texts: list[str] = []

    for dirpath, dirnames, filenames_in_dir in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames_in_dir:
            filenames.add(name)
            full = Path(dirpath) / name
            rel = full.relative_to(root_path).as_posix()
            try:
                size = full.stat().st_size
            except OSError as exc:
                result.errors.append(f"{rel}: cannot stat file ({exc})")
                continue
            if not rules.is_scannable(rel, size):
                continue
            text = _read_text(full)
            if text is None:
                result.errors.append(f"{rel}: skipped (binary or unreadable)")
                continue
            result.files_scanned += 1
            if name in rules.SKILL_DOC_NAMES:
                doc_texts.append(text)
            ext = Path(name).suffix.lower()
            for match in rules.check_lines(text.splitlines(), ext):
                result.findings.append(Finding(
                    rule_id=match.rule.rule_id,
                    severity=match.rule.severity,
                    path=rel,
                    line=match.line,
                    evidence=match.evidence,
                    message=match.rule.message,
                    remediation=match.rule.remediation,
                    heuristic=match.rule.heuristic,
                ))

    for meta_rule in rules.check_metadata(filenames, doc_texts):
        result.findings.append(Finding(
            rule_id=meta_rule.rule_id,
            severity=meta_rule.severity,
            path=".",
            line=0,
            evidence="(directory-level check)",
            message=meta_rule.message,
            remediation=meta_rule.remediation,
        ))

    result.findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    return result
