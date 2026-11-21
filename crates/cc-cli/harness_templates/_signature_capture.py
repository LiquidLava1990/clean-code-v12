"""Signature snapshot capture / compare logic (used by Layer 2)."""
from __future__ import annotations

import inspect
import json
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping


def _annotation_repr(ann: Any) -> str:
    """Stable string form for a type annotation."""
    if ann is inspect.Parameter.empty or ann is inspect.Signature.empty:
        return ""
    if isinstance(ann, type):
        return f"{ann.__module__}.{ann.__qualname__}"
    return repr(ann)


_REPR_FAILURE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    RuntimeError, AttributeError, TypeError, ValueError, RecursionError,
    OSError, LookupError, ArithmeticError, UnicodeError,
)


def _default_repr(default: Any) -> str:
    """Stable string form for a parameter default."""
    if default is inspect.Parameter.empty:
        return "<empty>"
    try:
        return repr(default)
    except _REPR_FAILURE_EXCEPTIONS:
        return f"<unrepr:{type(default).__name__}>"


def _params(sig: inspect.Signature) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for p in sig.parameters.values():
        out.append(
            {
                "name": p.name,
                "kind": p.kind.name,
                "default": _default_repr(p.default),
                "annotation": _annotation_repr(p.annotation),
            }
        )
    return out


def _signature_for(obj: Any) -> dict[str, Any] | None:
    """Capture a signature dict, or None if uncapturable."""
    try:
        sig = inspect.signature(obj)
    except (TypeError, ValueError):
        return None
    return {
        "params": _params(sig),
        "return": _annotation_repr(sig.return_annotation),
    }


def _is_public(name: str) -> bool:
    return not name.startswith("_")


def capture_module(mod: ModuleType) -> dict[str, dict[str, Any]]:
    """Snapshot every public callable defined in ``mod`` (re-exports filtered)."""
    out: dict[str, dict[str, Any]] = {}
    mod_name = getattr(mod, "__name__", None)
    for name in dir(mod):
        if not _is_public(name):
            continue
        try:
            obj = getattr(mod, name)
        except _REPR_FAILURE_EXCEPTIONS:
            continue
        if not callable(obj):
            continue
        owner = getattr(obj, "__module__", None)
        if owner is not None and mod_name is not None and owner != mod_name:
            continue
        sig = _signature_for(obj)
        if sig is None:
            continue
        qualname = getattr(obj, "__qualname__", name)
        out[name] = {
            "qualname": qualname,
            "kind": "class" if inspect.isclass(obj) else "function",
            **sig,
        }
    return out


def capture_all(modules: Mapping[str, ModuleType]) -> dict[str, dict[str, Any]]:
    """Build the full snapshot dict, keyed by ``<module>:<name>``."""
    snap: dict[str, dict[str, Any]] = {}
    for mod_name, mod in modules.items():
        for sym, sig in capture_module(mod).items():
            snap[f"{mod_name}:{sym}"] = sig
    return snap


def load_snapshot(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_snapshot(path: Path, snap: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(snap, indent=2, sort_keys=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(payload + "\n")
