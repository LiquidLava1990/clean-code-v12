"""Layer 7 helper -- suppression-comment audit.

Walks each in-scope ``.py`` file with regexes to count occurrences of
linter / type-checker suppressions:

  - ``# cc-allow:<rule>``       -- Clean Code V12 suppression
  - ``# noqa[: <rule>]``         -- flake8 / ruff
  - ``# pylint: disable=<rule>`` -- pylint
  - ``# type: ignore[: <rule>]`` -- mypy
  - ``# pyright: ignore[<rule>]``-- pyright

Snapshot: ``{file: {rule: count}}``. Test: live <= snapshot per
(file, rule). Adding a new suppression requires a deliberate snapshot
bump -- forces explicit acknowledgement that "I'm muting a check."

Rule key naming:
  - The TOOL is part of the key so ``cc-allow:R-EXC-BARE`` and
    ``noqa:E501`` cannot collide. Format: ``<tool>:<rule>`` (or
    ``<tool>:*`` when the suppression had no rule).
"""
from __future__ import annotations

import re
from pathlib import Path

# Each entry: (tool_name, regex). Capture group 1 is the rule (or empty
# string when the suppression is rule-less). Patterns are intentionally
# permissive -- false positives in this layer are cheap (they just bake
# into the baseline); false negatives let real suppressions slip past.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cc-allow", re.compile(r"#[ \t]*cc-allow[ \t]*:[ \t]*([\w\-./]+)")),
    ("noqa", re.compile(r"#[ \t]*noqa(?:[ \t]*:[ \t]*([\w\-,\t ]+))?")),
    ("pylint", re.compile(r"#[ \t]*pylint[ \t]*:[ \t]*disable[ \t]*=[ \t]*([\w\-,\t ]+)")),
    ("mypy", re.compile(r"#[ \t]*type[ \t]*:[ \t]*ignore(?:[ \t]*\[[ \t]*([\w\-,\t ]+)[ \t]*\])?")),
    ("pyright", re.compile(r"#[ \t]*pyright[ \t]*:[ \t]*ignore(?:[ \t]*\[[ \t]*([\w\-,\t ]+)[ \t]*\])?")),
)


def _read_text(path: Path) -> str:
    """Read source text; tolerate undecodable bytes."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _split_rules(raw: str) -> list[str]:
    """Split a captured rule blob (``E501,W292``) into individual rule names."""
    if not raw:
        return ["*"]
    parts = [p.strip() for p in raw.split(",")]
    cleaned = [p for p in parts if p]
    return cleaned or ["*"]


def _scan_one_pattern(
    tool: str, pattern: re.Pattern[str], text: str,
) -> dict[str, int]:
    """Counts contributed by one ``(tool, pattern)`` to the snapshot."""
    counts: dict[str, int] = {}
    for match in pattern.finditer(text):
        for rule in _split_rules(match.group(1) or ""):
            key = f"{tool}:{rule}"
            counts[key] = counts.get(key, 0) + 1
    return counts


def suppressions_for_file(path: Path) -> dict[str, int]:
    """Return ``{tool:rule: count}`` for one source file (zeros omitted)."""
    text = _read_text(path)
    if not text:
        return {}
    counts: dict[str, int] = {}
    for tool, pattern in _PATTERNS:
        for key, n in _scan_one_pattern(tool, pattern, text).items():
            counts[key] = counts.get(key, 0) + n
    return counts
