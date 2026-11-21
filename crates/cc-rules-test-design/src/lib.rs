//! `cc-rules-test-design` — Family 28 (test design + mutation health) probe pack.
//!
//! Phase 6 of Clean Code V12. Covers test-structure quality axes the
//! Phase-4 [`cc-rules-tests`] pack does NOT touch — fused from the
//! testifylint / jest-extended / pytest-style / mutation-testing OSS
//! delta. Every rule in this pack is gated on
//! [`helpers::is_test_file_path`]; non-test files are silent.
//!
//! - [`unconditional_assert_true`]   — REAL.  `assert!(true)` etc.
//! - [`disabled_test`]                — REAL.  skip / ignore / xit without reason.
//! - [`shared_setup_in_assertion`]    — REAL.  no Arrange-Act-Assert separation.
//! - [`flaky_iteration`]              — REAL.  loop over time/random + assertion inside.
//! - [`no_negative_case`]             — STUB.  needs whole-program test-name companion check.
//! - [`assertion_count_zero`]         — REAL.  zero assertion calls AND no `?` operator.
//! - [`private_helper_imported_into_test`] — STUB. needs visibility cross-check.
//! - [`non_isolated_state`]           — STUB.  defers to `cc.fragile.shared_global_state`.
//! - [`test_imports_test_module`]     — REAL.  test file imports another test file.
//! - [`gigantic_test_function`]       — REAL.  test body > 100 logical lines.
//!
//! Phase 11 — pytest PT-family long-tail (ruff PT004 / PT006 / PT012 /
//! PT017 / PT018 mined from the OSS-linter delta study):
//!
//! - [`pt_fixture_returns_value`]            — REAL.  bare `@pytest.fixture` returning a value.
//! - [`pt_parametrize_no_kwargs`]            — REAL.  CSV parametrize names instead of tuple.
//! - [`pt_raises_simple_block`]              — REAL.  `with pytest.raises(...)` body > 1 stmt.
//! - [`pt_assert_in_finally`]                — REAL.  `assert` in `finally:` swallows error.
//! - [`pt_missing_test_classname_prefix`]    — REAL.  test-file class missing `Test` prefix.
//!
//! See [`BuiltinTestDesignPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod assertion_count_zero;
pub mod disabled_test;
pub mod flaky_iteration;
pub mod gigantic_test_function;
mod helpers;
pub mod no_negative_case;
pub mod non_isolated_state;
mod pack;
pub mod private_helper_imported_into_test;
pub mod pt_assert_in_finally;
pub mod pt_fixture_returns_value;
pub mod pt_missing_test_classname_prefix;
pub mod pt_parametrize_no_kwargs;
pub mod pt_raises_simple_block;
pub mod shared_setup_in_assertion;
pub mod test_imports_test_module;
pub mod unconditional_assert_true;

#[cfg(test)]
mod tests;

pub use pack::BuiltinTestDesignPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinTestDesignPack::PACK_ID;
