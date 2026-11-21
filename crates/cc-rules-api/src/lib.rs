//! `cc-rules-api` — Family 9 (API + schema drift) probe pack.
//!
//! Phases 4 + 8 of Clean Code V12. Ships six probes covering the
//! surfaces where API contracts silently drift away from their consumers:
//!
//! - [`client_server_drift`] — STUB. Whole-program client TS types vs
//!   server response shapes; deferred to Phase 5 when the persistent
//!   CPG store can hold both sides simultaneously.
//! - [`breaking_change_no_version`] — STUB. Diff-aware `OpenAPI` /
//!   proto bump detection; deferred to Phase 5 when the runner gains
//!   a git-history side-channel.
//! - [`schema_vs_db_drift`] — STUB. ORM model + migration cross-reference;
//!   deferred to Phase 5 alongside the other cross-file probes.
//! - [`response_shape_drift`] — heuristic: a public handler-shaped
//!   function returns structurally-different shapes from different
//!   `return` statements.
//!
//! Phase 8 (Batch H — API drift probes mined from the OSS delta study):
//!
//! - [`struct_tag_required`] — Go exported struct field with no
//!   serialisation tag in a struct that already tags its peers
//!   (golangci-lint `musttag`).
//! - [`errcode_collision`] — same `ErrCode` literal
//!   constructed at multiple sites. Single-file conservative shadow
//!   pending cross-file aggregation in the kernel.
//!
//! See [`BuiltinApiPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod breaking_change_no_version;
pub mod client_server_drift;
pub mod errcode_collision;
mod helpers;
mod pack;
pub mod response_shape_drift;
pub mod schema_vs_db_drift;
pub mod struct_tag_required;

#[cfg(test)]
mod tests;

pub use pack::BuiltinApiPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinApiPack::PACK_ID;
