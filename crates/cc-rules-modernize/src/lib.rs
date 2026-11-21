//! `cc-rules-modernize` — Family 26 (modernization / version-skew) pack.
//!
//! Phase 6 shipped the original ten probes; Phase 8 added ten more
//! mined from ruff `FURB`/`SIM`/`UP`/`PTH`/`FLY`, eslint-plugin-unicorn,
//! and clippy. The complete roster — twenty modernization probes
//! covering valid-syntax-but-superseded patterns:
//!
//! Phase 6:
//! - [`string_format_legacy`] — Python `"%s" % x` (printf-style).
//! - [`deprecated_typing_alias`] — Python `typing.List` / `typing.Dict` etc.
//! - [`os_path_join`] — Python `os.path.join` over `pathlib.Path`.
//! - [`var_for_let`] — JavaScript `var` declarations.
//! - [`commonjs_require`] — JavaScript `require(...)` instead of ESM `import`.
//! - [`callbacks_over_promises`] — last param `cb`/`callback`/`done` heuristic.
//! - [`deprecated_unwrap`] — Rust `.unwrap()` outside test files.
//! - [`legacy_format_macro`] — Rust `format!("{}", x)` instead of `.to_string()`.
//! - [`thread_spawn_no_join`] — Rust `thread::spawn` with discarded handle.
//! - [`sync_in_async_runtime`] — Go `sync.Mutex` inside goroutine context.
//!
//! Phase 8:
//! - [`simplify_boolean_expr`] — `if x { true } else { false }` → `x`.
//! - [`template_over_concat`] — `"a " + x + " b"` → template / f-string.
//! - [`no_array_for_each`] — JS `arr.forEach(cb)` → `for…of`.
//! - [`use_pathlib_over_os`] — Python `os.path.{exists,isfile,…}` → `pathlib.Path`.
//! - [`bare_reraise_lossy`] — Python `raise X` inside `except` w/o `from e`.
//! - [`dict_literal_over_call`] — Python `dict(a=1)` → `{"a": 1}`.
//! - [`list_call_in_set_call`] — Python `set(list(x))` → `set(x)`.
//! - [`string_format_to_fstring`] — Python `"…".format(…)` → f-string.
//! - [`deprecated_unittest_aliases`] — `assertEquals` → `assertEqual` etc.
//! - [`consistent_function_scoping`] — JS nested fn that captures nothing.
//!
//! Phase 9 (Batch K — Python-deep-dive probes mined from ruff G/SIM/TRY/ICN/S):
//! - [`logging_fstring`] — `logger.info(f"…")` formats eagerly (ruff G004).
//! - [`try_consider_else`] — trailing `try:` body belongs in `else:` (ruff TRY300).
//! - [`collapsible_if`] — `if a: if b: …` → `if a and b:` (ruff SIM102).
//! - [`banned_import_alias`] — `import numpy as numpy` (ruff ICN001).
//! - [`try_except_pass`] — `try: … except E: pass` silent catch (ruff S110).
//!
//! Phase 10 (Python long-tail — DJ-Django, NPY-NumPy, PD-pandas):
//! - [`django_url_path_param_required`] — `path('<param>/', ...)` without
//!   a converter prefix (`<int:>`, `<slug:>`, ...) (ruff DJ001 family).
//! - [`django_locals_in_render`] — `render(req, tpl, locals())` leaks
//!   every local binding into the template (ruff DJ012).
//! - [`numpy_legacy_random`] — `np.random.rand(...)` etc — replace with
//!   `np.random.default_rng()` per NumPy 2.0 (ruff NPY002).
//! - [`pandas_chained_assignment`] — `df[col][row] = value` triggers
//!   `SettingWithCopyWarning` (ruff PD901).
//!
//! Phase 10 (Rust long-tail — clippy):
//! - [`manual_let_else`] — `let x = match y { Some(v) => v, None => return };`
//!   superseded by 1.65 `let-else` (clippy `manual_let_else`).
//! - [`redundant_closure`] — `|x| f(x)` is just `f` (clippy `redundant_closure`).
//! - [`unnecessary_lazy_evaluations`] — `.unwrap_or_else(|| <lit>)` is just
//!   `.unwrap_or(<lit>)` (clippy `unnecessary_lazy_evaluations`).
//!
//! Phase 12 (final OSS long-tail sweep):
//! - [`python_walrus_for_assign_in_cond`] — `x = compute(); if x ...:` could
//!   collapse to `if (x := compute()) ...:` (PEP 572).
//! - [`python_match_case_for_chain`] — ≥3-arm `if/elif` on the same variable
//!   could become `match`/`case` (PEP 634).
//! - [`python_dataclass_for_class_with_init`] — class whose `__init__` only
//!   assigns parameters to `self` should be a `@dataclass` (PEP 557).
//!
//! See [`BuiltinModernizePack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod banned_import_alias;
pub mod bare_reraise_lossy;
pub mod callbacks_over_promises;
pub mod collapsible_if;
pub mod commonjs_require;
pub mod consistent_function_scoping;
pub mod deprecated_typing_alias;
pub mod deprecated_unittest_aliases;
pub mod deprecated_unwrap;
pub mod dict_literal_over_call;
pub mod django_locals_in_render;
pub mod django_url_path_param_required;
mod helpers;
pub mod legacy_format_macro;
pub mod list_call_in_set_call;
pub mod logging_fstring;
pub mod manual_let_else;
pub mod no_array_for_each;
pub mod numpy_legacy_random;
pub mod os_path_join;
mod pack;
pub mod pandas_chained_assignment;
pub mod python_dataclass_for_class_with_init;
pub mod python_match_case_for_chain;
pub mod python_walrus_for_assign_in_cond;
pub mod redundant_closure;
pub mod simplify_boolean_expr;
pub mod string_format_legacy;
pub mod string_format_to_fstring;
pub mod sync_in_async_runtime;
pub mod template_over_concat;
pub mod thread_spawn_no_join;
pub mod try_consider_else;
pub mod try_except_pass;
pub mod unnecessary_lazy_evaluations;
pub mod use_pathlib_over_os;
pub mod var_for_let;

#[cfg(test)]
mod tests;

pub use pack::BuiltinModernizePack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinModernizePack::PACK_ID;
