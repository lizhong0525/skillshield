"""Baseline (suppressions) file support.

A baseline is a JSON file listing fingerprints of known/accepted findings.
Matching findings are moved out of the active finding list so thresholds and
CI gates only react to *new* issues.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult

BASELINE_VERSION = 1


def load_baseline(path: str | Path) -> set[str]:
    """Load fingerprints from a baseline file. Raises ValueError on bad input."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline file is not valid JSON: {p}: {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("suppressions"), list):
        fps = data["suppressions"]
    elif isinstance(data, list):
        fps = data
    else:
        raise ValueError(
            f"baseline file has unexpected shape: {p} "
            "(expected {\"suppressions\": [...]} or a plain list)"
        )
    out = set()
    for item in fps:
        if isinstance(item, dict) and isinstance(item.get("fingerprint"), str):
            out.add(item["fingerprint"])
        elif isinstance(item, str):
            out.add(item)
    return out


def write_baseline(result: ScanResult, path: str | Path) -> None:
    """Write all current findings to a baseline file."""
    suppressions = [
        {
            "fingerprint": f.fingerprint,
            "rule_id": f.rule_id,
            "path": f.path,
            "message": f.message,
        }
        for f in sorted(result.findings, key=lambda f: f.fingerprint)
    ]
    payload = {
        "version": BASELINE_VERSION,
        "note": "Accepted findings. Delete an entry to re-enable it.",
        "suppressions": suppressions,
    }
    Path(path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def apply_baseline(result: ScanResult, fingerprints: set[str]) -> None:
    """Move findings whose fingerprint is in the baseline to `suppressed`."""
    kept, suppressed = [], []
    for f in result.findings:
        (suppressed if f.fingerprint in fingerprints else kept).append(f)
    result.findings = kept
    result.suppressed = suppressed
