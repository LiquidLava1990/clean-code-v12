//! `cc-rules-slop` — Family 1 (slop & drift) probe pack for Clean Code V12.
//!
//! Eight heuristic probes flagging the texture of LLM-emitted or
//! contractor-style code: fake-thoughtful names, defensive try/except over
//! pure code, premature abstractions, drift from project naming, and so on.
//!
//! # Public surface
//!
//! - Eight concrete [`cc_rules::Rule`] implementations under their topical
//!   modules (`fake_thoughtful_name`, `defensive_pure_fn`, …).
//! - [`BuiltinSlopPack`] — a [`cc_rules::RulePack`] that registers them.
//!
//! # Severity defaults
//!
//! Every slop rule defaults to [`cc_finding::Severity::Required`] —
//! adoption-friendly, never `Blocker`. Operators tighten via
//! `.cc/config.toml`.
//!
//! # Phase-2 deviations
//!
//! - `cc.slop.comment_vs_code` ships a heuristic only; the deep semantic
//!   "does the code do what the comment says" check is deferred to the
//!   LLM family in Phase 5 (see TODO at the top of
//!   [`comment_vs_code`]).
//! - `cc.slop.unused_helper` skips silently when the lifted batch lacks
//!   `CG_CALLS` / `REFERENCES` edges, mirroring `cc.shape.dead_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod comment_vs_code;
pub mod defensive_pure_fn;
pub mod drift_from_project;
pub mod fake_thoughtful_name;
mod helpers;
pub mod llm_texture;
pub mod over_commented_obvious;
mod pack;
pub mod premature_abstraction;
pub mod unused_helper;

#[cfg(test)]
mod tests;

pub use pack::BuiltinSlopPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinSlopPack::PACK_ID;
