//! `cc-rules-tests` — Family 8 (test quality) probe pack.
//!
//! Phases 4 + 8 of Clean Code V12. Ships ten probes — five real,
//! five Phase-4 stubs whose detection requires whole-program data
//! the kernel does not yet surface (test-execution history, mutation
//! testing results, signature comparison across mock and real impl):
//!
//! - [`assertion_free`] — REAL. A test that runs but asserts nothing.
//! - [`tests_the_mock`] — REAL. A test whose only assertions hit mock
//!   objects, never the real impl under test.
//! - [`mock_drift`] — STUB. Mock signature drifts from the real impl.
//! - [`flaky`] — STUB. Test passes / fails non-deterministically.
//! - [`coverage_hole_on_diff`] — STUB. Diff coverage gap.
//! - [`mutation_survivor_density`] — STUB. Surviving mutants per kLoC.
//! - [`truth_score`] — STUB. Composite truth metric.
//!
//! Phase 8 (Batch H — test-quality probes mined from the OSS delta study):
//!
//! - [`parallel_test_uses_shared_t`] — Go subtest captures outer
//!   `*testing.T` instead of the closure parameter (paralleltest /
//!   tparallel).
//! - [`testify_assertion_misuse`] — testify `Equal(t, got, expected)`
//!   reversal (testifylint, low-precision).
//! - [`assertion_free_jest`] — JS/TS Jest / Mocha test body with no
//!   `expect` / `assert` (eslint-plugin-jest expect-expect).
//!
//! Every rule in this pack is gated on
//! `helpers::is_test_file_path` — non-test files are silent. Phase-8
//! probes intentionally RUN inside test files (their job is to assess
//! test quality), so they only honour the path gate, not the existing
//! source-skip helpers.
//!
//! See [`BuiltinTestsPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod assertion_free;
pub mod assertion_free_jest;
pub mod coverage_hole_on_diff;
pub mod flaky;
mod helpers;
pub mod mock_drift;
pub mod mutation_survivor_density;
mod pack;
pub mod parallel_test_uses_shared_t;
pub mod testify_assertion_misuse;
pub mod tests_the_mock;
pub mod truth_score;

#[cfg(test)]
mod tests;

pub use pack::BuiltinTestsPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinTestsPack::PACK_ID;
