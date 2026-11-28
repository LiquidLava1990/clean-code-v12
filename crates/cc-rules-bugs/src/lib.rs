//! `cc-rules-bugs` — Family 3 (bugs / correctness) probe pack.
//!
//! Phases 3 + 7 + 8 + 9 + 10 + 11 + 12 of Clean Code V12. Ships fifty-four probes.
//!
//! Phase 3 (original seven):
//!
//! - [`null_propagation`] — Optional/Nullable into a non-Optional sink.
//! - [`off_by_one`] — index arithmetic on `for i in 0..len(xs)` style loops.
//! - [`type_confusion`] — implicit `Any` / `interface{}` flowing into a
//!   typed binding.
//! - [`state_machine`] — close-then-read patterns on a single binding.
//! - [`time_bomb`] — hardcoded date strings + Y2038 risk literals.
//! - [`float_money`] — money in floats.
//! - [`locale_dependent`] — locale-dependent upper / lower / title casing
//!   on user input paths.
//!
//! Phase 7 (Batch E — bug correctness probes mined from the OSS delta study):
//!
//! - [`equals_hashcode_pair`] — `__eq__` / `equals` without `__hash__` /
//!   `hashCode`.
//! - [`identity_binary_expr`] — same expression both sides of `==` / `-` /
//!   `&` / `|` / `^`.
//! - [`cmp_to_nan`] — direct equality with `NaN`.
//! - [`shift_amount_oor`] — bit-shift constant amount ≥ 32.
//! - [`format_string_drift`] — printf-style placeholder count ≠ arg count.
//! - [`regex_invalid`] — regex literal with structural defect.
//! - [`deferred_close_no_err`] — Go `defer x.Close()` swallowing an error.
//! - [`mutate_during_iteration`] — Python loop mutating its own collection.
//!
//! Phase 8 (Batch H — bug correctness probes mined from the OSS delta study):
//!
//! - [`tick_leak`] — Go `time.Tick(...)` outside `main` leaks the
//!   underlying ticker (staticcheck SA1015).
//! - [`dead_thread`] — Java/Kotlin `Thread t = new Thread(...)` with no
//!   `t.start()` (Error Prone DeadThread).
//! - [`always_throws`] — division by literal zero (Error Prone
//!   AlwaysThrows).
//! - [`use_after_move`] — Rust binding consumed and then re-used
//!   (clang-tidy bugprone-use-after-move).
//! - [`html_url_javascript`] — `href="javascript:..."` XSS sink
//!   (Sonar S5247).
//!
//! Phase 9 (Batch K — Python-deep-dive probes mined from ruff B0xx):
//!
//! - [`mutable_arg_default`] — `def f(x=[])` shared-default bug (ruff B006).
//! - [`unused_loop_variable`] — `for x in lst:` with body never reading
//!   `x` (ruff B007).
//! - [`fn_call_in_default_arg`] — `def f(x=time.time())` def-time-once
//!   evaluation (ruff B008).
//! - [`assert_with_tuple`] — `assert (x, y)` always-true tuple operand
//!   (ruff B011 / pyflakes F631).
//! - [`broad_pytest_raises`] — `pytest.raises(Exception)` masks
//!   unrelated failures (ruff B017).
//!
//! Phase 9 (Batch K — Go-deep-dive probes mined from staticcheck +
//! golangci):
//!
//! - [`body_close_missing`] — `*http.Response` without `defer
//!   resp.Body.Close()` (golangci `bodyclose`).
//! - [`errcheck_json`] — `json.Marshal` / `json.Unmarshal` whose error
//!   return is discarded (golangci `errchkjson`).
//! - [`err_named_inconsistently`] — Go error sentinel not prefixed with
//!   `Err` / `err` (golangci `errname`).
//! - [`nilerr`] — `if err != nil { return nil }` swallowing the error
//!   (golangci `nilerr`).
//!
//! Phase 9 (Batch K — Rust-deep-dive probes mined from clippy):
//!
//! - [`absurd_extreme_comparison`] — `x as u8 > 256` (clippy
//!   `absurd_extreme_comparisons`).
//! - [`bad_bit_mask`] — `x & 0 == 1` etc (clippy `bad_bit_mask`).
//! - [`cast_nan_to_int`] — `f64::NAN as u32` (clippy
//!   `cast_nan_to_int`).
//! - [`cast_possible_truncation`] — `large_u64 as u8` (clippy
//!   `cast_possible_truncation`).
//! - [`cast_precision_loss`] — `i64 as f32` (clippy
//!   `cast_precision_loss`).
//!
//! Phase 10 (Python long-tail mined from ruff FURB / ISC):
//!
//! - [`furb_implicit_int_str_concat`] — `"foo" "bar"` adjacent string
//!   literals (likely missing comma) (ruff ISC001).
//! - [`furb_dict_get_with_none_default`] — `d.get(key, None)` redundant
//!   `None` argument (ruff FURB186).
//! - [`furb_for_else_loop_unused`] — `for x in items: ... else:` body
//!   without `break` — `else` always runs.
//!
//! Phase 10 (Batch L — multi-language cross-cutting bug probes):
//!
//! - [`duplicate_dict_keys`] — Python `{"a": 1, "a": 2}` / JS
//!   `{ a: 1, a: 2 }` (ruff F601 / ESLint `no-dupe-keys`).
//!
//! Phase 10 (Rust long-tail mined from clippy):
//!
//! - [`arithmetic_side_effects`] — `+`/`-`/`*`/`/`/`%` on integers
//!   in security-sensitive crates without an explicit overflow choice
//!   (clippy `arithmetic_side_effects`).
//! - [`as_conversions`] — `<ident> as <numeric_ty>` cast hides the
//!   conversion choice (clippy `as_conversions`).
//! - [`clone_on_ref_ptr`] — `arc_var.clone()` reads as a deep clone
//!   (clippy `clone_on_ref_ptr`).
//! - [`default_numeric_fallback`] — module-level numeric literal
//!   silently defaults to `i32` / `f64` (clippy
//!   `default_numeric_fallback`).
//!
//! Phase 11 (Go long-tail mined from `go vet`):
//!
//! - [`govet_unreachable_code`]   — statement after `return` / `panic` /
//!   `os.Exit` / `log.Fatal*` (go vet `unreachable`).
//! - [`govet_lostcancel`]         — `ctx, _ := context.WithCancel(...)`
//!   discards the cancel func (go vet `lostcancel`).
//! - [`govet_assign_to_self`]     — `x = x` self-assignment (go vet
//!   `assign`).
//! - [`govet_copylocks`]          — copy of `sync.Mutex` / `sync.WaitGroup`
//!   value (go vet `copylocks`).
//! - [`govet_unkeyed_composite`]  — `Foo{1, "bar"}` positional struct
//!   literal (go vet `composites`).
//!
//! Phase 12 (final OSS long-tail sweep):
//!
//! - [`govet_nilness_check`]            — post-nil-check use of a var
//!   reassigned to nil (go vet `nilness`).
//! - [`govet_printf_format`]            — Go-specific printf verb /
//!   arg-count mismatch (`%v`, `%+v`, `%T`, `%q`) (go vet `printf`).
//! - [`govet_struct_tag_well_formed`]   — malformed `key:"value"` pair
//!   in a Go struct tag (go vet `structtag`).
//! - [`python_assert_in_production`]    — `assert ...` in non-test
//!   Python code (Bandit B101).
//!
//! See [`BuiltinBugsPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.
//!
//! Batch 2 (Python reliability probes, tree-sitter based):
//!
//! - [`callout_under_lock`]                 — external call made while a
//!   lock is held.
//! - [`one_ticket_per_refusal`]             — ticket filing without a
//!   prior dedupe check.
//! - [`unbounded_detail_text`]              — unbounded text stored in a
//!   detail field.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod absurd_extreme_comparison;
pub mod always_throws;
pub mod arithmetic_side_effects;
pub mod as_conversions;
pub mod assert_with_tuple;
pub mod bad_bit_mask;
pub mod body_close_missing;
pub mod broad_pytest_raises;
pub mod callout_under_lock;
pub mod cast_nan_to_int;
pub mod cast_possible_truncation;
pub mod cast_precision_loss;
pub mod clone_on_ref_ptr;
pub mod cmp_to_nan;
pub mod dead_thread;
pub mod default_numeric_fallback;
pub mod deferred_close_no_err;
pub mod duplicate_dict_keys;
pub mod equals_hashcode_pair;
pub mod err_named_inconsistently;
pub mod errcheck_json;
pub mod float_money;
pub mod fn_call_in_default_arg;
pub mod format_string_drift;
pub mod furb_dict_get_with_none_default;
pub mod furb_for_else_loop_unused;
pub mod furb_implicit_int_str_concat;
pub mod govet_assign_to_self;
pub mod govet_copylocks;
pub mod govet_lostcancel;
pub mod govet_nilness_check;
pub mod govet_printf_format;
pub mod govet_struct_tag_well_formed;
pub mod govet_unkeyed_composite;
pub mod govet_unreachable_code;
mod helpers;
pub mod html_url_javascript;
pub mod identity_binary_expr;
pub mod locale_dependent;
pub mod mutable_arg_default;
pub mod mutate_during_iteration;
pub mod nilerr;
pub mod null_propagation;
pub mod off_by_one;
pub mod one_ticket_per_refusal;
mod pack;
pub mod python_assert_in_production;
mod python_calls;
mod python_signatures;
pub mod regex_invalid;
pub mod shift_amount_oor;
pub mod state_machine;
pub mod tick_leak;
pub mod time_bomb;
pub mod type_confusion;
pub mod unbounded_detail_text;
pub mod unused_loop_variable;
pub mod use_after_move;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_phase11;

#[cfg(test)]
mod test_phase12;

pub use pack::BuiltinBugsPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinBugsPack::PACK_ID;
