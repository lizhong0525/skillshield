"""Human-readable and JSON report rendering."""

from __future__ import annotations

import json

from . import __version__
from .models import SEVERITIES, ScanResult

DISCLAIMER = (
    "SkillShield findings are static-analysis hints, not a security guarantee. "
    "A clean scan does not prove a skill is safe; a flagged line may still be "
    "benign. Review flagged code manually."
)


def _sev_tag(severity: str) -> str:
    return severity.upper().ljust(8)


def render_text(result: ScanResult, threshold: str) -> str:
    lines = []
    lines.append(f"SkillShield {__version__} - scan of {result.root}")
    lines.append(f"Files scanned: {result.files_scanned}")
    if result.errors:
        lines.append(f"Warnings: {len(result.errors)} (files skipped/unreadable)")
        for err in result.errors:
            lines.append(f"  ! {err}")

    counts = result.severity_counts()
    summary = "  ".join(f"{s}:{counts[s]}" for s in reversed(SEVERITIES) if counts[s])
    lines.append(f"Findings: {len(result.findings)} active"
                 + (f" ({summary})" if summary else "")
                 + (f", {len(result.suppressed)} suppressed" if result.suppressed else ""))
    lines.append("")

    if not result.findings:
        lines.append("No findings above information level were detected.")
    for f in result.findings:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        heur = " [heuristic]" if f.heuristic else ""
        lines.append(f"[{_sev_tag(f.severity)}] {f.rule_id}{heur} {loc}")
        lines.append(f"  {f.message}")
        lines.append(f"  Evidence:    {f.evidence}")
        lines.append(f"  Remediation: {f.remediation}")
        lines.append("")

    breaches = result.breaches(threshold)
    verdict = "FAIL" if breaches else "PASS"
    lines.append(f"Threshold (--fail-on {threshold}): {verdict} "
                 f"({len(breaches)} finding(s) at or above threshold)")
    lines.append("")
    lines.append(f"Note: {DISCLAIMER}")
    return "\n".join(lines)


def render_json(result: ScanResult, threshold: str) -> str:
    breaches = result.breaches(threshold)
    payload = {
        "tool": "skillshield",
        "version": __version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "errors": result.errors,
        "threshold": threshold,
        "verdict": "fail" if breaches else "pass",
        "summary": {
            "active": len(result.findings),
            "suppressed": len(result.suppressed),
            "by_severity": {k: v for k, v in result.severity_counts().items() if v},
        },
        "findings": [f.to_dict() for f in result.findings],
        "suppressed_findings": [f.to_dict() for f in result.suppressed],
        "disclaimer": DISCLAIMER,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
