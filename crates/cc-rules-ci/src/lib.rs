//! `cc-rules-ci` — Family 17 (CI + build pipeline) probe pack.
//!
//! Phase 4 of Clean Code V12. Ships five probes:
//!
//! - [`flaky_test_history`] — STUB; needs CI-history ingestion (Phase 5).
//! - [`slow_test`] — STUB; needs runtime-data ingestion (Phase 5).
//! - [`missing_step`] — flags a CI workflow file that mentions zero of
//!   `lint` / `test` / `typecheck`.
//! - [`lockfile_uncommitted`] — flags a manifest whose companion lockfile
//!   is absent from the batch.
//! - [`hook_bypass_in_history`] — STUB; needs git-log walker (Phase 5).
//!
//! See [`BuiltinCiPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod flaky_test_history;
mod helpers;
pub mod hook_bypass_in_history;
pub mod lockfile_uncommitted;
pub mod missing_step;
mod pack;
pub mod slow_test;

#[cfg(test)]
mod tests;

pub use pack::BuiltinCiPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinCiPack::PACK_ID;
