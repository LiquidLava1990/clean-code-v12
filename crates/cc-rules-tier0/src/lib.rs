//! `cc-rules-tier0` — the eight Tier-0 forever rules (Phase 1 slice).
//!
//! This crate ships:
//!
//! - Eight concrete [`cc_rules::Rule`] implementations (`shape::*`, `error::*`).
//! - [`BuiltinTier0Pack`] — a [`cc_rules::RulePack`] that registers them.
//!
//! # Forever-rule self-host
//!
//! The eight rules dogfood themselves: every public item carries doc
//! comments (`deny(missing_docs)`), no function exceeds 50 LOC, no
//! nesting deeper than three levels, no bare `unwrap` / `expect` outside
//! tests, and the `R-ERR-BARE` rule must not contain a bare `except`
//! itself.
//!
//! # Phase-1 deviation
//!
//! Per-rule thresholds in [`cc_config::RuleConfig::thresholds`] are not
//! yet wired (waiting for the Wave-2 config decoder). Each rule reads
//! its threshold from a private `const` matching the literal default
//! from `docs/design/TIER_0_ALGORITHMS.md`. The TODO marker
//! `// TODO(W2): wire ctx.config thresholds` flags every site.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
mod helpers;
pub mod meta;
mod pack;
pub mod shape;
pub mod type_coverage;

#[cfg(test)]
mod tests;

pub use pack::BuiltinTier0Pack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinTier0Pack::PACK_ID;
