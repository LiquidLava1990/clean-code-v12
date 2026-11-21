"""Regenerate every harness snapshot from the codebase.

Produces:
  - ``snapshots/signatures.json``         (Layer 2)
  - ``snapshots/exception_shapes.json``   (Layer 3)
  - ``snapshots/dependencies.json``       (Layer 4)
  - ``snapshots/slop_markers.json``       (Layer 5)
  - ``snapshots/public_api.json``         (Layer 6)
  - ``snapshots/suppressions.json``       (Layer 7)

Run after a deliberate change. Commit the resulting JSON alongside the
behavior change with a message describing the delta.

Usage:
    python tests/cc_harness/regenerate_signatures.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

_HARNESS_DIR = Path(__file__).resolve().parent
_TESTS_DIR = _HARNESS_DIR.parent
_REPO = _TESTS_DIR.parent
for p in (_REPO, _TESTS_DIR):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

from cc_harness._dependency_capture import imports_for_file  # noqa: E402
from cc_harness._discovery import HARNESS_REPO_ROOT, discover  # noqa: E402
from cc_harness._exception_shape import (  # noqa: E402
    shape_for_file, shape_to_jsonable,
)
from cc_harness._import_helper import safe_import  # noqa: E402
from cc_harness._marker_capture import markers_for_file  # noqa: E402
from cc_harness._public_api_capture import public_api_for  # noqa: E402
from cc_harness._signature_capture import (  # noqa: E402
    capture_all, write_snapshot,
)
from cc_harness._suppression_capture import suppressions_for_file  # noqa: E402


def _write_json(path: Path, payload: Any) -> None:
    """Atomic JSON dump with stable formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, indent=2, sort_keys=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(body + "\n")


def _file_key(p: Path) -> str:
    """Repo-relative POSIX key used by file-level snapshots."""
    return p.resolve().relative_to(HARNESS_REPO_ROOT).as_posix()


def _import_modules() -> tuple[dict, list[str], list[str]]:
    """Import every discovered module, partitioning the outcomes."""
    modules: dict = {}
    skipped: list[str] = []
    failed: list[str] = []
    for target in discover():
        outcome = safe_import(target)
        if outcome.ok and outcome.module is not None:
            modules[target.dotted] = outcome.module
        elif outcome.skipped:
            skipped.append(f"{target.dotted} ({outcome.skipped_reason})")
        else:
            failed.append(f"{target.dotted}: {outcome.failure!r}")
    return modules, skipped, failed


def _write_exception_shapes(path: Path) -> int:
    out: dict[str, list[dict]] = {}
    seen: set[str] = set()
    for target in discover():
        key = _file_key(target.source)
        if key in seen:
            continue
        seen.add(key)
        out[key] = shape_to_jsonable(shape_for_file(target.source))
    _write_json(path, out)
    return sum(len(v) for v in out.values())


def _write_dependencies(path: Path) -> int:
    out: dict[str, list[str]] = {
        target.dotted: imports_for_file(target.source)
        for target in discover()
    }
    _write_json(path, out)
    return sum(len(v) for v in out.values())


def _file_count_snapshot(
    capture: Callable[[Path], dict[str, int]],
) -> dict[str, dict[str, int]]:
    """Build a ``{file_key: {kind: count}}`` map by applying ``capture``."""
    out: dict[str, dict[str, int]] = {}
    seen: set[str] = set()
    for target in discover():
        key = _file_key(target.source)
        if key in seen:
            continue
        seen.add(key)
        counts = capture(target.source)
        if counts:
            out[key] = counts
    return out


def _write_file_count_snapshot(
    path: Path, capture: Callable[[Path], dict[str, int]],
) -> int:
    """Write a per-file count snapshot via ``capture`` and return the total."""
    out = _file_count_snapshot(capture)
    _write_json(path, out)
    return sum(sum(c.values()) for c in out.values())


def _write_public_api(path: Path, modules: dict) -> int:
    out = {name: public_api_for(mod) for name, mod in modules.items()}
    _write_json(path, out)
    return sum(len(rec.get("names", [])) for rec in out.values())


def _write_signatures(path: Path, modules: dict) -> int:
    snap = capture_all(modules)
    write_snapshot(path, snap)
    return len(snap)


def _snapshot_paths() -> dict[str, Path]:
    snaps = _HARNESS_DIR / "snapshots"
    return {
        "signatures": snaps / "signatures.json",
        "exceptions": snaps / "exception_shapes.json",
        "dependencies": snaps / "dependencies.json",
        "markers": snaps / "slop_markers.json",
        "public_api": snaps / "public_api.json",
        "suppressions": snaps / "suppressions.json",
    }


def _emit_summary(
    counts: dict[str, int], modules: dict,
    skipped: list[str], failed: list[str],
) -> None:
    """Emit the human-readable + machine-parseable summary lines."""
    n_mods = len(modules)
    print(f"wrote {counts['signatures']} signatures across {n_mods} modules")
    print(f"wrote {counts['exceptions']} try-block shapes")
    print(f"wrote {counts['dependencies']} import edges across {n_mods} modules")
    print(f"wrote {counts['markers']} slop markers")
    print(f"wrote {counts['public_api']} public-API entries")
    print(f"wrote {counts['suppressions']} suppression comments")
    print(f"skipped {len(skipped)} modules (missing externals)")
    if failed:
        print(f"FAILED to import {len(failed)} modules:")
        for line in failed[:10]:
            print(f"  {line}")


def main() -> int:
    paths = _snapshot_paths()
    modules, skipped, failed = _import_modules()
    counts = {
        "signatures": _write_signatures(paths["signatures"], modules),
        "exceptions": _write_exception_shapes(paths["exceptions"]),
        "dependencies": _write_dependencies(paths["dependencies"]),
        "markers": _write_file_count_snapshot(paths["markers"], markers_for_file),
        "public_api": _write_public_api(paths["public_api"], modules),
        "suppressions": _write_file_count_snapshot(
            paths["suppressions"], suppressions_for_file,
        ),
    }
    _emit_summary(counts, modules, skipped, failed)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
