//! `cc-rules-anti-fragility` — Family 23 (anti-fragility / test brittleness)
//! probe pack.
//!
//! Phase 4 of Clean Code V12. Ships four probes that all gate on
//! [`helpers::is_test_file_path`] — they only fire inside test files,
//! staying silent on production code.
//!
//! - [`timing_assumption`] — sleep-based test, time-based logic.
//! - [`network_in_test`] — test reaches an external host.
//! - [`order_dependent`] — test passes only in declaration order
//!   (Phase-4 STUB; wired in Phase 5).
//! - [`shared_global_state`] — tests mutating module-level state.
//!
//! See [`BuiltinAntiFragilityPack`] for the registered
//! [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod helpers;
pub mod network_in_test;
pub mod order_dependent;
mod pack;
pub mod shared_global_state;
pub mod timing_assumption;

#[cfg(test)]
mod tests;

pub use pack::BuiltinAntiFragilityPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinAntiFragilityPack::PACK_ID;
