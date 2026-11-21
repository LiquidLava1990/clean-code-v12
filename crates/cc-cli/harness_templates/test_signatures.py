"""Layer 2 -- public signature snapshot.

Captures ``inspect.signature`` for every public callable in every imported
module, compares against ``snapshots/signatures.json``. Drift fails.

After a deliberate API change, regenerate via ``ccv12 harness regenerate <repo>``.
"""
from __future__ import annotations

from pathlib import Path
from types import ModuleType
from typing import Dict

import pytest

from cc_harness._signature_capture import capture_all, load_snapshot


SNAPSHOT_PATH: Path = (
    Path(__file__).resolve().parent / "snapshots" / "signatures.json"
)


def test_signatures_snapshot_exists() -> None:
    assert SNAPSHOT_PATH.exists(), (
        f"signature snapshot missing at {SNAPSHOT_PATH}. "
        "Run `ccv12 harness regenerate <repo>` to create it."
    )


def _format_drift(drift: list[str]) -> str:
    joined = "\n".join(drift[:25])
    more = f"\n... and {len(drift) - 25} more" if len(drift) > 25 else ""
    return (
        "signature drift detected:\n"
        f"{joined}{more}\n\n"
        "If the change is intentional run "
        "`ccv12 harness regenerate <repo>` and recommit the snapshot."
    )


def test_signatures_match_snapshot(
    imported_modules: Dict[str, ModuleType],
) -> None:
    if not SNAPSHOT_PATH.exists():
        pytest.skip("snapshot not yet generated")
    expected = load_snapshot(SNAPSHOT_PATH)
    live = capture_all(imported_modules)
    drift: list[str] = []
    for key, want in expected.items():
        got = live.get(key)
        if got is None:
            drift.append(f"REMOVED {key}")
            continue
        if got != want:
            drift.append(f"CHANGED {key}\n  expected={want}\n  actual={got}")
    new_keys = sorted(set(live) - set(expected))
    for key in new_keys:
        drift.append(f"ADDED {key} (not in snapshot)")
    if drift:
        raise AssertionError(_format_drift(drift))
