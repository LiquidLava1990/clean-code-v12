//! `cc-rules-history` — Family 18 (git history rot) probe pack.
//!
//! Phase 4 of Clean Code V12. Ships five probes:
//!
//! - [`churn_complexity_hotspot`] — STUB; needs git-blame + complexity
//!   correlation (Phase 5).
//! - [`parameter_creep`] — STUB; needs cross-revision symbol diff
//!   (Phase 5).
//! - [`partial_rewrites`] — STUB; needs cross-revision diff (Phase 5).
//! - [`todo_aging`] — REAL but non-aging variant: flags every TODO /
//!   FIXME / XXX / HACK comment as [`Severity::Nit`]. The semantic
//!   "older than 90d" requires git-blame plumbing; the non-aging
//!   variant is the closest signal we can ship today.
//! - [`bus_factor`] — STUB; needs blame-author histogram (Phase 5).
//!
//! See [`BuiltinHistoryPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bus_factor;
pub mod churn_complexity_hotspot;
mod helpers;
mod pack;
pub mod parameter_creep;
pub mod partial_rewrites;
pub mod todo_aging;

#[cfg(test)]
mod tests;

pub use pack::BuiltinHistoryPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinHistoryPack::PACK_ID;
