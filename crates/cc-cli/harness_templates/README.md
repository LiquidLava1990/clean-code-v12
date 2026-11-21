# Clean Code V12 pre-refactor harness

Seven-layer guard against refactor regressions and slop accumulation,
scaffolded by `ccv12 harness init <repo>`. The harness is light on purpose
-- no behavioural mocks, no service stand-ins -- so it stays fast and
stable while a multi-file refactor is in flight.

## Layers

### 1. Import smoke -- `test_imports.py`
- Walks every in-scope `.py` file (skipping `__pycache__`, `.venv/`,
  `_archive/`, `test_*.py`, `*_test.py`, `setup.py`, and entrypoint
  scripts that execute on import).
- Each module is its own parametrized test case (one failing import never
  masks others).
- A `ModuleNotFoundError` whose missing dep is in `KNOWN_EXTERNAL_DEPS`
  becomes `pytest.skip`. Anything else FAILS -- those are real bugs.

### 2. Public signature snapshot -- `test_signatures.py`
- For each successfully imported module, captures every public callable
  via `inspect.signature` (parameters, kinds, defaults, return annotation).
- Snapshot at `snapshots/signatures.json`, keyed by `module:name`.
- Re-exports are filtered (only symbols whose `__module__` matches the
  importing module) so renaming a re-exported name doesn't alarm.
- The test fails on any drift: REMOVED, CHANGED, or ADDED keys.

### 3. AST exception-handler shape -- `test_exception_handlers.py`
- Parses each `.py` file with `ast`, captures every `try/except`:
  enclosing function, line, per-handler exception types, and a verdict:
  `reraise` (always re-raises), `swallow` (never raises), or `mixed`.
- Snapshot at `snapshots/exception_shapes.json`.
- The test flags any verdict change. The dangerous direction is
  `swallow -> reraise` / `swallow -> mixed`: a previously-silent safety
  net is now propagating.

### 4. Module dependency snapshot -- `test_dependencies.py`
- For every Python module, walks the AST for `import X` /
  `from X import Y` and captures the set of TOP-LEVEL imported module
  names.
- Snapshot at `snapshots/dependencies.json`, keyed by dotted module
  name -> sorted list of imports.
- Test asserts live walk == snapshot. New imports OR removed imports
  both fail -- catches architectural drift (domain reaches into infra,
  cycle introduction) AND dead-code import leaks.

### 5. Slop-marker density -- `test_slop_markers.py`
- Counts occurrences of `TODO`, `FIXME`, `HACK`, `XXX`, `WORKAROUND`,
  `KLUDGE`, `DEPRECATED` per file.
- Snapshot at `snapshots/slop_markers.json`: `{file: {marker: count}}`.
- Test asserts live count <= snapshot count per (file, marker). New
  markers FAIL; reductions are silent (cleaning up old debt is good).
- Forces explicit acknowledgement: "I'm leaving debt AND admitting it
  in the snapshot."

### 6. Public-surface `__all__` lock -- `test_public_api.py`
- For every imported module, captures explicit `__all__` if defined,
  else an implicit list of top-level public names defined IN that
  module (re-exports + imported submodules filtered).
- Snapshot at `snapshots/public_api.json`:
  `{module: {"kind": "explicit"|"implicit", "names": [...]}}`.
- Test asserts live == snapshot. Silent additions or removals of
  public exports fail.

### 7. Suppression-comment audit -- `test_suppressions.py`
- Scans for `# cc-allow:<rule>`, `# noqa[: <rule>]`, `# pylint:
  disable=<rule>`, `# type: ignore[<rule>]`, `# pyright: ignore[<rule>]`.
- Snapshot at `snapshots/suppressions.json`:
  `{file: {tool:rule: count}}`.
- Test asserts live count <= snapshot per (file, tool:rule). New
  suppressions fail -- forces explicit acknowledgement that "I'm
  muting a check."

## When does each layer fire

| Refactor change                           | L1 | L2 | L3 | L4 | L5 | L6 | L7 |
|-------------------------------------------|----|----|----|----|----|----|----|
| Module rename / split                     | Y  | Y  | Y  | Y  | Y  | Y  | Y  |
| Function param rename / reorder           |    | Y  |    |    |    |    |    |
| New keyword-only arg with default         |    | Y  |    |    |    |    |    |
| Default value changed                     |    | Y  |    |    |    |    |    |
| Public class deleted                      |    | Y  |    |    |    | Y  |    |
| `except Exception: pass` -> re-raise      |    |    | Y  |    |    |    |    |
| Narrowing `Exception` to `ValueError`     |    |    | Y  |    |    |    |    |
| Adding new try block                      |    |    | Y  |    |    |    |    |
| New `import x` (architectural drift)      |    |    |    | Y  |    |    |    |
| Dead import left after deletion           |    |    |    | Y  |    |    |    |
| New `# TODO` / `# FIXME`                  |    |    |    |    | Y  |    |    |
| New public top-level def                  |    | Y  |    |    |    | Y  |    |
| Silent removal from `__all__`             |    |    |    |    |    | Y  |    |
| New `# noqa: <rule>` suppression          |    |    |    |    |    |    | Y  |
| New `# type: ignore` / `# pylint: disable`|    |    |    |    |    |    | Y  |

## Workflow

```bash
ccv12 harness init <repo>          # scaffold + baseline snapshot (all 7 layers)
# ... fix findings, refactor ...
ccv12 harness verify <repo>        # confirm no drift across all 7 layers
ccv12 harness regenerate <repo>    # ratify deliberate changes (rebuilds all 7 snapshots)
```

The `ccv12 harness regenerate` step MUST be paired with a commit message
that describes the delta -- the snapshot diff is the source of truth
for code review.

## Project-local config (optional)

Create `tests/cc_harness/config.py` to extend the discovery defaults:

```python
EXTRA_EXTERNAL_DEPS = ("my_proprietary_sdk",)
EXTRA_SKIP_BASENAMES = ("custom_entrypoint.py",)
```

## Constraints

- Only stdlib + pytest. No `unittest.mock`, no fakers.
- No source files outside `tests/cc_harness/` are modified by the harness.
- Snapshots commit alongside code; treat them like checked-in fixtures.
