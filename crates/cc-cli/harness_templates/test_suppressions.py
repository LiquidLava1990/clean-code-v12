"""Layer 7 -- suppression-comment audit.

Counts ``# cc-allow:``, ``# noqa:``, ``# pylint: disable=``,
``# type: ignore``, and ``# pyright: ignore`` per file. The test
asserts live count <= snapshot count per (file, tool:rule). Adding a
new suppression fails -- forces explicit acknowledgement that "I'm
muting a check."
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cc_harness._discovery import HARNESS_REPO_ROOT, discover
from cc_harness._suppression_capture import suppressions_for_file


SNAPSHOT_PATH: Path = (
    Path(__file__).resolve().parent / "snapshots" / "suppressions.json"
)


def _file_key(p: Path) -> str:
    """Stable key: repo-relative POSIX path."""
    return p.resolve().relative_to(HARNESS_REPO_ROOT).as_posix()


def _capture_live() -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    seen: set[str] = set()
    for target in discover():
        key = _file_key(target.source)
        if key in seen:
            continue
        seen.add(key)
        counts = suppressions_for_file(target.source)
        if counts:
            out[key] = counts
    return out


def _load_snapshot() -> dict[str, dict[str, int]]:
    if not SNAPSHOT_PATH.exists():
        return {}
    with SNAPSHOT_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_suppression_snapshot_exists() -> None:
    assert SNAPSHOT_PATH.exists(), (
        f"suppression snapshot missing at {SNAPSHOT_PATH}. "
        "Run `cc harness regenerate <repo>` to create it."
    )


def _diff_one_file(
    path: str, live_counts: dict[str, int], baseline: dict[str, int],
) -> list[str]:
    """Drift entries for one file: only NEW suppressions fail."""
    drift: list[str] = []
    for rule, live_n in live_counts.items():
        baseline_n = baseline.get(rule, 0)
        if live_n > baseline_n:
            delta = live_n - baseline_n
            drift.append(
                f"{path}: +{delta} new {rule} "
                f"(was {baseline_n}, now {live_n})"
            )
    return drift


def _format_drift(drift: list[str]) -> str:
    joined = "\n".join(drift[:40])
    more = f"\n... and {len(drift) - 40} more" if len(drift) > 40 else ""
    return (
        "new suppression comments detected:\n"
        f"{joined}{more}\n\n"
        "Either remove the suppression (fix the underlying issue) OR run "
        "`cc harness regenerate <repo>` to acknowledge it explicitly."
    )


def test_suppressions_within_baseline() -> None:
    if not SNAPSHOT_PATH.exists():
        pytest.skip("snapshot not yet generated")
    baseline = _load_snapshot()
    live = _capture_live()
    drift: list[str] = []
    for path, live_counts in live.items():
        drift.extend(_diff_one_file(path, live_counts, baseline.get(path, {})))
    if drift:
        raise AssertionError(_format_drift(drift))
