//! `cc-rules-completeness` — Family 25 structural-completeness probes.
//!
//! Detects the *absence* of the quality markers that turn working code
//! into observable, debuggable, evolvable systems. Covers four
//! disciplines: granular errors, a meta-registry for every function,
//! canonical names, and the function → registry → typed error → event
//! chain.
//!
//! # Sub-families
//!
//! | Module        | Probes                                     |
//! |---------------|--------------------------------------------|
//! | [`observe`]   | tracers + observability (4)                |
//! | [`meta`]      | meta-registry + leasing (5)                |
//! | [`contract`]  | contracts + invariants (5)                 |
//! | [`error`]     | granular errors + canonical naming (5)     |
//! | [`decoration`]| canonical decoration patterns (4)          |
//! | [`chain`]     | function → registry → error → event chain (5) |
//! | [`safety`]    | safety + coverage (Phase 10) (2)           |
//!
//! 30 probes total. Phase-2 grade: heuristic detection. The LLM-verified
//! variants land in Phase 5.
//!
//! # Severity defaults
//!
//! Most probes default to [`cc_finding::Severity::Required`]. Only three
//! are [`cc_finding::Severity::Blocker`] — the ones that represent real
//! bugs rather than missing decoration:
//!
//! - `cc.error.no_typed_class`
//! - `cc.error.errcode_collision`
//! - `cc.error.swallowed_with_log`
//!
//! # Self-host gate
//!
//! Every probe public surface carries a doc comment
//! (`#![deny(missing_docs)]`). No `unsafe` blocks. No bare
//! `unwrap`/`expect` outside tests. The crate dogfoods its own probes
//! when the kernel runs over the workspace.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod chain;
pub mod contract;
pub mod decoration;
pub mod error;
mod helpers;
pub mod meta;
pub mod observe;
mod pack;
pub mod safety;

#[cfg(test)]
mod tests;

pub use pack::BuiltinCompletenessPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinCompletenessPack::PACK_ID;
