"""AST-level exception-handler shape capture (used by Layer 3).

For every ``try`` block in every in-scope .py file we record:
  - the enclosing function (qualified, e.g. ``outer.inner``)
  - the line number of the try
  - per-handler:
      * ``types``: tuple of exception type names caught
      * ``verdict``: one of {"reraise", "swallow", "mixed"}
      * ``body_kinds``: lightweight summary of node kinds in the body

Verdicts:
  ``reraise`` -> handler ALWAYS unwinds (every path raises / re-raises).
  ``swallow`` -> handler NEVER unwinds (returns / passes / logs).
  ``mixed``   -> some paths raise, others don't (e.g. conditional re-raise).

Refactor risk:
  Going swallow -> reraise (or mixed) means callers that previously got
  None now get an exception -- the high-risk change Layer 3 catches.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class HandlerShape:
    types: tuple[str, ...]
    verdict: str  # "reraise" | "swallow" | "mixed"
    body_kinds: tuple[str, ...]


@dataclass(frozen=True)
class TryShape:
    function: str
    line: int
    handlers: tuple[HandlerShape, ...]


def _exc_type_name(node: ast.expr | None) -> str:
    if node is None:
        return "BARE"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Tuple):
        return "(" + ",".join(_exc_type_name(e) for e in node.elts) + ")"
    return ast.unparse(node) if hasattr(ast, "unparse") else "<expr>"


def _enclosing_function(stack: list[str]) -> str:
    return ".".join(stack) if stack else "<module>"


def _path_raises(stmts: list[ast.stmt]) -> bool:
    """Returns True if executing this statement list ALWAYS exits via raise."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, ast.Raise):
        return True
    if isinstance(last, (ast.Return, ast.Continue, ast.Break)):
        return False
    if isinstance(last, ast.If):
        if not last.orelse:
            return False
        return _path_raises(last.body) and _path_raises(last.orelse)
    if isinstance(last, ast.Try):
        try_raises = _path_raises(last.body)
        handlers_raise = all(_path_raises(h.body) for h in last.handlers)
        return try_raises and handlers_raise
    return False


def _path_can_raise(stmts: list[ast.stmt]) -> bool:
    """Returns True if any path through these statements raises."""
    for stmt in stmts:
        if isinstance(stmt, ast.Raise):
            return True
        for child in ast.walk(stmt):
            if isinstance(child, ast.Raise):
                return True
    return False


def _classify(handler_body: list[ast.stmt]) -> str:
    always = _path_raises(handler_body)
    can = _path_can_raise(handler_body)
    if always:
        return "reraise"
    if can:
        return "mixed"
    return "swallow"


def _body_kinds(handler_body: list[ast.stmt]) -> tuple[str, ...]:
    return tuple(type(stmt).__name__ for stmt in handler_body)


def _handler_types(type_node: ast.expr | None) -> tuple[str, ...]:
    if type_node is None:
        return ("BARE",)
    if isinstance(type_node, ast.Tuple):
        return tuple(_exc_type_name(e) for e in type_node.elts)
    return (_exc_type_name(type_node),)


class _TryVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.tries: list[TryShape] = []
        self._stack: list[str] = []

    def _visit_func(self, node: ast.AST, name: str) -> None:
        self._stack.append(name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node, node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node, node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_func(node, node.name)

    def _capture_try(self, node: ast.Try) -> None:
        handlers: list[HandlerShape] = []
        for h in node.handlers:
            handlers.append(
                HandlerShape(
                    types=_handler_types(h.type),
                    verdict=_classify(h.body),
                    body_kinds=_body_kinds(h.body),
                )
            )
        self.tries.append(
            TryShape(
                function=_enclosing_function(self._stack),
                line=node.lineno,
                handlers=tuple(handlers),
            )
        )

    def visit_Try(self, node: ast.Try) -> None:
        self._capture_try(node)
        self.generic_visit(node)


def shape_for_file(path: Path) -> list[TryShape]:
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return []
    v = _TryVisitor()
    v.visit(tree)
    return v.tries


def shape_to_jsonable(shapes: list[TryShape]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for s in shapes:
        out.append(
            {
                "function": s.function,
                "line": s.line,
                "handlers": [
                    {
                        "types": list(h.types),
                        "verdict": h.verdict,
                        "body_kinds": list(h.body_kinds),
                    }
                    for h in s.handlers
                ],
            }
        )
    return out
