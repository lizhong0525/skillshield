"""Core data model for SkillShield findings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# Ordered from least to most severe. Index is used for threshold comparisons.
SEVERITIES = ("info", "low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    """Return the rank of a severity, or -1 for unknown values."""
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return -1


@dataclass(frozen=True)
class Finding:
    """A single scan result."""

    rule_id: str
    severity: str
    path: str  # path relative to the scanned root, forward slashes
    line: int  # 1-based line number; 0 for directory-level findings
    evidence: str
    message: str
    remediation: str
    heuristic: bool = False

    @property
    def fingerprint(self) -> str:
        """Stable identity used by the baseline file.

        Deliberately excludes the line number so small edits around a known
        finding do not silently un-suppress it.
        """
        raw = "|".join([self.rule_id, self.path, self.evidence.strip()])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "message": self.message,
            "remediation": self.remediation,
            "heuristic": self.heuristic,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanResult:
    """Aggregated result of scanning one directory."""

    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def severity_counts(self) -> dict:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def breaches(self, threshold: str) -> list[Finding]:
        """Findings at or above the given severity threshold."""
        rank = severity_rank(threshold)
        return [f for f in self.findings if severity_rank(f.severity) >= rank]
