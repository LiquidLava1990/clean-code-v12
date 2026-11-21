//! `cc-rules-deploy` — Family 13 (deployment) probe pack.
//!
//! Phase 4 of Clean Code V12. Ships four probes:
//!
//! - [`no_rollback_path`] — irreversible filesystem op without a guard.
//! - [`big_bang_migration`] — STUB; needs git-history walker (Phase 5).
//! - [`missing_feature_flag`] — risky-name function without a flag check.
//! - [`stale_flag`] — STUB; needs flag-history scanner (Phase 5).
//!
//! See [`BuiltinDeployPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod big_bang_migration;
mod helpers;
pub mod missing_feature_flag;
pub mod no_rollback_path;
mod pack;
pub mod stale_flag;

#[cfg(test)]
mod tests;

pub use pack::BuiltinDeployPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinDeployPack::PACK_ID;
