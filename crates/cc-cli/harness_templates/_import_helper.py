"""Shared import helper used by all three harness layers.

``safe_import`` runs ``importlib.import_module`` for a discovered module
after configuring ``sys.path`` to include the repo root. Returns an
``ImportOutcome`` describing one of:
  - imported (module object available)
  - skipped (a known external dependency was missing)
  - failed (an unexpected error -- the test fails)
"""
from __future__ import annotations

import importlib
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Optional

from ._discovery import DiscoveredModule, is_known_external


@dataclass
class ImportOutcome:
    """Result of attempting to import one discovered module."""

    module: Optional[ModuleType]
    skipped_reason: Optional[str]
    failure: Optional[BaseException]

    @property
    def ok(self) -> bool:
        return self.module is not None

    @property
    def skipped(self) -> bool:
        return self.skipped_reason is not None


def _ensure_path(root: Path) -> None:
    s = str(root)
    if s in sys.path:
        sys.path.remove(s)
    sys.path.insert(0, s)


_IMPORT_FAILURE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    AttributeError, ValueError, TypeError, RuntimeError, OSError,
    SyntaxError, NameError, KeyError, IndexError, LookupError,
    UnicodeError, AssertionError, ArithmeticError,
)


def _classify_module_not_found(
    exc: ModuleNotFoundError, dotted: str,
) -> ImportOutcome:
    """ModuleNotFoundError -> skip on known external, failure otherwise."""
    missing = exc.name or ""
    if missing == dotted:
        return ImportOutcome(None, None, exc)
    if is_known_external(missing):
        return ImportOutcome(None, f"missing external: {missing}", None)
    return ImportOutcome(None, None, exc)


def _detect_known_external_in_message(msg: str) -> Optional[str]:
    """First known-external token referenced in ``msg`` (or None)."""
    for tok in msg.split():
        cleaned = tok.strip("'\"().,:;").split(".", 1)[0]
        if cleaned and is_known_external(cleaned):
            return cleaned
    return None


def _classify_import_error(exc: ImportError) -> ImportOutcome:
    """ImportError -> skip when message mentions a known external dep."""
    cleaned = _detect_known_external_in_message(str(exc))
    if cleaned is not None:
        return ImportOutcome(
            None, f"missing external (ImportError: {cleaned})", None,
        )
    return ImportOutcome(None, None, exc)


def safe_import(target: DiscoveredModule) -> ImportOutcome:
    """Import ``target.dotted`` (skip on known external, fail otherwise)."""
    _ensure_path(target.sys_path_root)
    try:
        mod = importlib.import_module(target.dotted)
    except ModuleNotFoundError as exc:
        return _classify_module_not_found(exc, target.dotted)
    except ImportError as exc:
        return _classify_import_error(exc)
    except _IMPORT_FAILURE_EXCEPTIONS as exc:  # pragma: no cover
        return ImportOutcome(None, None, exc)
    return ImportOutcome(mod, None, None)
