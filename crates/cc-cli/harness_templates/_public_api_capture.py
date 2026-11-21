"""Layer 6 helper -- public-surface ``__all__`` lock.

For every successfully imported module we record either its explicit
``__all__`` list OR an implicit one derived from top-level public names
(those not starting with ``_``). The snapshot stores
``{module: sorted_list}`` and the test asserts live == snapshot, so any
silent addition or removal of a public export is caught.

The implicit fallback is important: most projects don't bother with
``__all__`` but still have a meaningful public surface. Snapshotting
the implicit list lets the harness lock the surface without forcing a
project-wide ``__all__`` migration.
"""
from __future__ import annotations

import inspect
from types import ModuleType
from typing import Any


def _explicit_all(mod: ModuleType) -> list[str] | None:
    """Return a sorted list of ``mod.__all__`` if defined; else None."""
    raw = getattr(mod, "__all__", None)
    if raw is None:
        return None
    try:
        names = [str(x) for x in raw]
    except TypeError:
        return None
    return sorted(set(names))


def _is_re_export_or_import(obj: Any, mod_name: str | None) -> bool:
    """True if ``obj`` is an imported module or a callable owned elsewhere."""
    if inspect.ismodule(obj):
        return True
    owner = getattr(obj, "__module__", None)
    if owner is None or mod_name is None:
        return False
    return owner != mod_name


def _implicit_public(mod: ModuleType) -> list[str]:
    """Top-level public names (no underscore prefix) defined IN ``mod``."""
    mod_name = getattr(mod, "__name__", None)
    out: list[str] = []
    for name in vars(mod):
        if name.startswith("_"):
            continue
        obj: Any = getattr(mod, name, None)
        if _is_re_export_or_import(obj, mod_name):
            continue
        out.append(name)
    return sorted(set(out))


def public_api_for(mod: ModuleType) -> dict[str, Any]:
    """Capture ``mod``'s surface as ``{"kind": str, "names": list[str]}``."""
    explicit = _explicit_all(mod)
    if explicit is not None:
        return {"kind": "explicit", "names": explicit}
    return {"kind": "implicit", "names": _implicit_public(mod)}
