"""Shared pytest fixtures for the pre-refactor harness.

Inserts the discovered scope root onto ``sys.path`` and exposes a
session-scoped import cache so signature / exception-shape tests don't
re-import the same modules.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Dict

import pytest

_HARNESS_DIR = Path(__file__).resolve().parent
_TESTS_DIR = _HARNESS_DIR.parent
_REPO_ROOT = _TESTS_DIR.parent
for p in (_REPO_ROOT, _TESTS_DIR):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

from cc_harness._discovery import DiscoveredModule, discover  # noqa: E402
from cc_harness._import_helper import ImportOutcome, safe_import  # noqa: E402


@pytest.fixture(scope="session")
def discovered_modules() -> list[DiscoveredModule]:
    return discover()


@pytest.fixture(scope="session")
def imported_modules(
    discovered_modules: list[DiscoveredModule],
) -> Dict[str, ModuleType]:
    """Eagerly import everything; downstream tests reuse the result."""
    out: Dict[str, ModuleType] = {}
    for target in discovered_modules:
        outcome: ImportOutcome = safe_import(target)
        if outcome.ok and outcome.module is not None:
            out[target.dotted] = outcome.module
    return out
