"""Layer 5 -- slop-marker density.

Counts ``TODO`` / ``FIXME`` / ``HACK`` / ``XXX`` / ``WORKAROUND`` /
``KLUDGE`` / ``DEPRECATED`` per file. The test asserts live count <=
snapshot count per (file, marker). New markers FAIL -- they require a
deliberate snapshot bump (an explicit "yes, I'm leaving debt behind").
Reduced counts pass silently (cleaning up old TODOs is encouraged).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cc_harness._discovery import HARNESS_REPO_ROOT, discover
from cc_harness._marker_capture import markers_for_file


SNAPSHOT_PATH: Path = (
    Path(__file__).resolve().parent / "snapshots" / "slop_markers.json"
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
        counts = markers_for_file(target.source)
        if counts:
            out[key] = counts
    return out


def _load_snapshot() -> dict[str, dict[str, int]]:
    if not SNAPSHOT_PATH.exists():
        return {}
    with SNAPSHOT_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_slop_marker_snapshot_exists() -> None:
    assert SNAPSHOT_PATH.exists(), (
        f"slop-marker snapshot missing at {SNAPSHOT_PATH}. "
        "Run `cc harness regenerate <repo>` to create it."
    )


def _diff_one_file(
    path: str, live_counts: dict[str, int], baseline: dict[str, int],
) -> list[str]:
    """Drift entries for one file: only NEW markers fail."""
    drift: list[str] = []
    for marker, live_n in live_counts.items():
        baseline_n = baseline.get(marker, 0)
        if live_n > baseline_n:
            delta = live_n - baseline_n
            drift.append(
                f"{path}: +{delta} new {marker} "
                f"(was {baseline_n}, now {live_n})"
            )
    return drift


def _format_drift(drift: list[str]) -> str:
    joined = "\n".join(drift[:40])
    more = f"\n... and {len(drift) - 40} more" if len(drift) > 40 else ""
    return (
        "new slop markers detected:\n"
        f"{joined}{more}\n\n"
        "Either fix the marker, OR run `cc harness regenerate <repo>` to "
        "acknowledge the debt explicitly."
    )


def test_slop_markers_within_baseline() -> None:
    if not SNAPSHOT_PATH.exists():
        pytest.skip("snapshot not yet generated")
    baseline = _load_snapshot()
    live = _capture_live()
    drift: list[str] = []
    for path, live_counts in live.items():
        drift.extend(_diff_one_file(path, live_counts, baseline.get(path, {})))
    if drift:
        raise AssertionError(_format_drift(drift))
