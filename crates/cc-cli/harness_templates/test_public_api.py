"""Layer 6 -- public-surface ``__all__`` lock.

For every imported module we capture either explicit ``__all__`` or an
implicit list (top-level public names defined in that module). The test
asserts live == snapshot. Adding or removing a public export fails;
ratify intentional changes with ``ccv12 harness regenerate <repo>``.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType
from typing import Any, Dict

import pytest

from cc_harness._public_api_capture import public_api_for


SNAPSHOT_PATH: Path = (
    Path(__file__).resolve().parent / "snapshots" / "public_api.json"
)


def _load_snapshot() -> dict[str, dict[str, Any]]:
    if not SNAPSHOT_PATH.exists():
        return {}
    with SNAPSHOT_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _capture_live(
    imported: Dict[str, ModuleType],
) -> dict[str, dict[str, Any]]:
    return {name: public_api_for(mod) for name, mod in imported.items()}


def test_public_api_snapshot_exists() -> None:
    assert SNAPSHOT_PATH.exists(), (
        f"public-API snapshot missing at {SNAPSHOT_PATH}. "
        "Run `ccv12 harness regenerate <repo>` to create it."
    )


def _diff_one_module(
    module: str, expected: dict[str, Any], live: dict[str, dict[str, Any]],
) -> list[str]:
    """Drift entries for one module's public surface."""
    got = live.get(module)
    if got is None:
        return [f"MODULE LOST: {module}"]
    exp_kind = expected.get("kind")
    got_kind = got.get("kind")
    if exp_kind != got_kind:
        return [f"{module}: kind {exp_kind} -> {got_kind}"]
    exp_names = list(expected.get("names", []))
    got_names = list(got.get("names", []))
    if exp_names == got_names:
        return []
    added = sorted(set(got_names) - set(exp_names))
    removed = sorted(set(exp_names) - set(got_names))
    msg = [f"PUBLIC API DRIFT: {module} ({exp_kind})"]
    if added:
        msg.append(f"  +exports: {added}")
    if removed:
        msg.append(f"  -exports: {removed}")
    return msg


def _format_drift(drift: list[str]) -> str:
    joined = "\n".join(drift[:40])
    more = f"\n... and {len(drift) - 40} more" if len(drift) > 40 else ""
    return (
        "public-API drift:\n"
        f"{joined}{more}\n\n"
        "If intentional, run `ccv12 harness regenerate <repo>` and recommit."
    )


def test_public_api_match_snapshot(
    imported_modules: Dict[str, ModuleType],
) -> None:
    if not SNAPSHOT_PATH.exists():
        pytest.skip("snapshot not yet generated")
    expected = _load_snapshot()
    live = _capture_live(imported_modules)
    drift: list[str] = []
    for module, want in expected.items():
        drift.extend(_diff_one_module(module, want, live))
    new_modules = sorted(set(live) - set(expected))
    for module in new_modules:
        names = live[module].get("names", [])
        drift.append(f"NEW MODULE PUBLIC API: {module} (exports={names})")
    if drift:
        raise AssertionError(_format_drift(drift))
