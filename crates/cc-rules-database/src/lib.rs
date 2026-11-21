//! `cc-rules-database` — Family 10 (database) probe pack.
//!
//! Phase 4 of Clean Code V12. Ships six probes:
//!
//! - [`missing_index`] — STUB; query-log + EXPLAIN integration is Phase-5 work.
//! - [`missing_fk`] — STUB; migration cross-reference deferred until persistent CPG.
//! - [`json_blob_hellscape`] — JSON columns for structured-looking field names.
//! - [`locking_migration`] — `ALTER TABLE` without `CONCURRENTLY` / `INPLACE`.
//! - [`missing_backfill`] — `ADD COLUMN ... NOT NULL` without `DEFAULT`.
//! - [`select_star_hot`] — `SELECT *` literals outside test files.
//!
//! See [`BuiltinDatabasePack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod helpers;
pub mod json_blob_hellscape;
pub mod locking_migration;
pub mod missing_backfill;
pub mod missing_fk;
pub mod missing_index;
mod pack;
pub mod select_star_hot;

#[cfg(test)]
mod tests;

pub use pack::BuiltinDatabasePack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinDatabasePack::PACK_ID;
