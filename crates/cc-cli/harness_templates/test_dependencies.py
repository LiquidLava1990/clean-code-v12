"""Layer 4 -- module dependency snapshot.

For every in-scope ``.py`` file we capture the set of TOP-LEVEL imports
(``import x`` and ``from x.y import z`` -> ``x``; relative imports
ignored) and assert the live walk matches the snapshot exactly. New
imports OR removed imports both fail; ratify intentional changes via
``ccv12 harness regenerate <repo>``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cc_harness._dependency_capture import imports_for_file
from cc_harness._discovery import discover


SNAPSHOT_PATH: Path = (
    Path(__file__).resolve().parent / "snapshots" / "dependencies.json"
)


def _capture_live() -> dict[str, list[str]]:
    """Build the live ``{module_dotted: sorted_imports}`` map."""
    out: dict[str, list[str]] = {}
    for target in discover():
        out[target.dotted] = imports_for_file(target.source)
    return out


def _load_snapshot() -> dict[str, list[str]]:
    if not SNAPSHOT_PATH.exists():
        return {}
    with SNAPSHOT_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_dependencies_snapshot_exists() -> None:
    assert SNAPSHOT_PATH.exists(), (
        f"dependency snapshot missing at {SNAPSHOT_PATH}. "
        "Run `ccv12 harness regenerate <repo>` to create it."
    )


def _diff_module(
    module: str, expected: list[str], live: dict[str, list[str]],
) -> list[str]:
    """Drift entries for one module's import set."""
    got = live.get(module)
    if got is None:
        return [f"REMOVED MODULE: {module} (was importing {expected})"]
    if got == expected:
        return []
    added = sorted(set(got) - set(expected))
    removed = sorted(set(expected) - set(got))
    msg = [f"DEPS DRIFT: {module}"]
    if added:
        msg.append(f"  +imports: {added}")
    if removed:
        msg.append(f"  -imports: {removed}")
    return msg


def _format_drift(drift: list[str]) -> str:
    joined = "\n".join(drift[:40])
    more = f"\n... and {len(drift) - 40} more" if len(drift) > 40 else ""
    return (
        "module dependency drift:\n"
        f"{joined}{more}\n\n"
        "If intentional, run `ccv12 harness regenerate <repo>` and recommit."
    )


def test_dependencies_match_snapshot() -> None:
    if not SNAPSHOT_PATH.exists():
        pytest.skip("snapshot not yet generated")
    expected = _load_snapshot()
    live = _capture_live()
    drift: list[str] = []
    for module, deps in expected.items():
        drift.extend(_diff_module(module, deps, live))
    for module in sorted(set(live) - set(expected)):
        drift.append(f"NEW MODULE: {module} (imports {live[module]})")
    if drift:
        raise AssertionError(_format_drift(drift))
