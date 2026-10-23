"""Read-only helpers for the clean fixture skill."""
from pathlib import Path


def list_notes(folder: str) -> list[str]:
    """Return Markdown file names inside `folder` without leaving it."""
    root = Path(folder).resolve()
    return sorted(p.name for p in root.glob("*.md") if p.parent == root)
