"""Layer 3 -- AST exception-handler shape diff.

Catches the dangerous refactor: a handler that previously SWALLOWED an
exception (returns / passes / logs without raise) is changed to RERAISE.
That breaks callers who relied on the safety-net behavior.

Snapshot file: ``snapshots/exception_shapes.json`` (per source file).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cc_harness._discovery import HARNESS_REPO_ROOT, discover
from cc_harness._exception_shape import shape_for_file, shape_to_jsonable


SNAPSHOT_PATH: Path = (
    Path(__file__).resolve().parent / "snapshots" / "exception_shapes.json"
)


def _file_key(p: Path) -> str:
    """Stable key for a source file: repo-relative POSIX path."""
    return p.resolve().relative_to(HARNESS_REPO_ROOT).as_posix()


def _capture_all() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    seen: set[str] = set()
    for target in discover():
        key = _file_key(target.source)
        if key in seen:
            continue
        seen.add(key)
        out[key] = shape_to_jsonable(shape_for_file(target.source))
    return out


def _load_snapshot() -> dict[str, list[dict[str, Any]]]:
    if not SNAPSHOT_PATH.exists():
        return {}
    with SNAPSHOT_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_exception_snapshot_exists() -> None:
    assert SNAPSHOT_PATH.exists(), (
        f"exception-shape snapshot missing at {SNAPSHOT_PATH}. "
        "Run `cc harness regenerate <repo>` to create it."
    )


def _diff_handlers(
    old_handlers: list[dict[str, Any]],
    new_handlers: list[dict[str, Any]],
) -> list[str]:
    """Return human-readable diff entries for one try block."""
    diffs: list[str] = []
    if len(old_handlers) != len(new_handlers):
        diffs.append(
            f"  handler count {len(old_handlers)} -> {len(new_handlers)}"
        )
        return diffs
    for idx, (old, new) in enumerate(zip(old_handlers, new_handlers)):
        if old.get("types") != new.get("types"):
            diffs.append(
                f"  handler[{idx}] types {old.get('types')} -> {new.get('types')}"
            )
        old_v = old.get("verdict", "")
        new_v = new.get("verdict", "")
        if old_v != new_v:
            diffs.append(
                f"  handler[{idx}] verdict {old_v} -> {new_v} "
                f"(types={new.get('types')})"
            )
    return diffs


def _diff_one_try(
    path: str, idx: int,
    old_try: dict[str, Any], new_tries: list[dict[str, Any]],
) -> list[str]:
    """Diff entries for one ``try`` block vs the same index in ``new_tries``."""
    if idx >= len(new_tries):
        return [
            f"{path}:{old_try.get('line')} try block removed "
            f"(was in {old_try.get('function')})"
        ]
    handler_diffs = _diff_handlers(
        old_try.get("handlers", []),
        new_tries[idx].get("handlers", []),
    )
    if not handler_diffs:
        return []
    return [
        f"{path}:{old_try.get('line')} ({old_try.get('function')})",
        *handler_diffs,
    ]


def _diff_one_file(
    path: str,
    old_tries: list[dict[str, Any]],
    live: dict[str, list[dict[str, Any]]],
) -> list[str]:
    """Drift entries for one source file path."""
    new_tries = live.get(path)
    if new_tries is None:
        return [f"FILE REMOVED: {path}"]
    drift: list[str] = []
    for idx, old_try in enumerate(old_tries):
        drift.extend(_diff_one_try(path, idx, old_try, new_tries))
    if len(new_tries) > len(old_tries):
        extra = len(new_tries) - len(old_tries)
        drift.append(f"{path} added {extra} new try block(s)")
    return drift


def _new_file_drift(
    expected: dict[str, list[dict[str, Any]]],
    live: dict[str, list[dict[str, Any]]],
) -> list[str]:
    """Drift entries for files that exist only in the live capture."""
    drift: list[str] = []
    for path in sorted(set(live) - set(expected)):
        if live[path]:
            drift.append(f"FILE ADDED: {path} ({len(live[path])} try blocks)")
    return drift


def _format_drift_message(drift: list[str]) -> str:
    """Render a drift list into a single AssertionError body."""
    joined = "\n".join(drift[:40])
    more = f"\n... and {len(drift) - 40} more entries" if len(drift) > 40 else ""
    return (
        "exception-handler shape drift:\n"
        f"{joined}{more}\n\n"
        "If intentional, run `cc harness regenerate <repo>` to update the "
        "snapshots and commit them."
    )


def test_exception_shapes_match_snapshot() -> None:
    if not SNAPSHOT_PATH.exists():
        pytest.skip("snapshot not yet generated")
    expected = _load_snapshot()
    live = _capture_all()

    drift: list[str] = []
    for path, old_tries in expected.items():
        drift.extend(_diff_one_file(path, old_tries, live))
    drift.extend(_new_file_drift(expected, live))

    if drift:
        raise AssertionError(_format_drift_message(drift))
