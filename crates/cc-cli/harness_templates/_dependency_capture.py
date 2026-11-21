"""Layer 4 helper -- AST module-dependency capture.

Walks every in-scope ``.py`` file under the repo root and captures the
set of TOP-LEVEL module names imported by each file:

  - ``import foo`` / ``import foo.bar`` -> ``foo``
  - ``from foo.bar import x`` -> ``foo``
  - ``from . import x`` (relative import) -> skipped (intra-package edge,
    not an architectural dependency for this layer)

The snapshot is keyed by the dotted module name and stores a sorted
list of imports. Any drift -- new import OR removed import -- triggers
the layer's drift assertion.

Why both directions matter:
  - NEW import of e.g. ``redis`` from a domain module signals the
    domain layer is reaching into infrastructure -- architectural drift.
  - REMOVED import without follow-up cleanup signals dead code (the
    ``import foo`` is gone but callers still expect ``foo`` to be wired).
"""
from __future__ import annotations

import ast
from pathlib import Path


def _top_level(name: str) -> str:
    """``foo.bar.baz`` -> ``foo``. Empty input maps to itself."""
    return name.split(".", 1)[0] if name else name


def _import_node_heads(node: ast.Import) -> list[str]:
    """Top-level names from an ``import x, y.z`` statement."""
    return [_top_level(alias.name) for alias in node.names if alias.name]


def _import_from_head(node: ast.ImportFrom) -> str:
    """Top-level name from ``from x.y import z``; empty if relative/bare."""
    if node.level and node.level > 0:
        return ""
    if node.module is None:
        return ""
    return _top_level(node.module)


def _heads_from_node(node: ast.AST) -> list[str]:
    """Return the top-level module heads contributed by ``node``."""
    if isinstance(node, ast.Import):
        return [h for h in _import_node_heads(node) if h]
    if isinstance(node, ast.ImportFrom):
        head = _import_from_head(node)
        return [head] if head else []
    return []


def _collect_imports(tree: ast.AST) -> set[str]:
    """Return the set of top-level imported module names from ``tree``."""
    out: set[str] = set()
    for node in ast.walk(tree):
        out.update(_heads_from_node(node))
    return out


def imports_for_file(path: Path) -> list[str]:
    """Return sorted top-level imports for one source file."""
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return []
    return sorted(_collect_imports(tree))
