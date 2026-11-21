"""Layer 1 -- import smoke.

For every discovered Python module, run ``importlib.import_module`` and
assert no exception. Missing known-external dependencies are skipped
(not failed) so the harness still passes on a fresh checkout without
optional packages.
"""
from __future__ import annotations

import pytest

from cc_harness._discovery import DiscoveredModule, discover
from cc_harness._import_helper import safe_import


_DISCOVERED: list[DiscoveredModule] = discover()


@pytest.mark.parametrize(
    "target",
    _DISCOVERED,
    ids=[m.id for m in _DISCOVERED],
)
def test_module_imports(target: DiscoveredModule) -> None:
    outcome = safe_import(target)
    if outcome.skipped:
        pytest.skip(outcome.skipped_reason or "missing external dependency")
    if outcome.failure is not None:
        raise AssertionError(
            f"import {target.dotted} failed: "
            f"{type(outcome.failure).__name__}: {outcome.failure}"
        )
    assert outcome.ok, f"import {target.dotted} returned no module"
