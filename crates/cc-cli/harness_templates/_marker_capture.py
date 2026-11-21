"""Layer 5 helper -- slop-marker density capture.

For each in-scope ``.py`` file we count occurrences of well-known
"I'll-fix-it-later" markers. The snapshot stores ``{file: {marker:
count}}``; the test asserts live counts are <= snapshot counts so any
NEW marker forces a deliberate snapshot bump (an explicit "yes, I'm
acknowledging this debt").

Counting strategy:
  - We scan the raw source as text, not the AST -- markers in comments
    OR strings both count, because both surface to humans reading code.
  - Each marker matches as a word boundary (so ``TODOLIST`` does not
    count as ``TODO``).
"""
from __future__ import annotations

import re
from pathlib import Path

# Canonical marker kinds. Order is informational only -- the snapshot
# is keyed by marker name. Keep this list short and stable: every marker
# is a category, not a synonym pile.
SLOP_MARKERS: tuple[str, ...] = (
    "TODO",
    "FIXME",
    "HACK",
    "XXX",
    "WORKAROUND",
    "KLUDGE",
    "DEPRECATED",
)

_MARKER_PATTERN: re.Pattern[str] = re.compile(
    r"\b(" + "|".join(SLOP_MARKERS) + r")\b"
)


def _read_text(path: Path) -> str:
    """Read source text; tolerate undecodable bytes."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def markers_for_file(path: Path) -> dict[str, int]:
    """Return ``{marker: count}`` for one source file (zeros omitted)."""
    text = _read_text(path)
    if not text:
        return {}
    counts: dict[str, int] = {}
    for match in _MARKER_PATTERN.finditer(text):
        kind = match.group(1)
        counts[kind] = counts.get(kind, 0) + 1
    return counts
