//! `cc-rules-architecture` — Family 20 (architecture / layering) probe pack.
//!
//! Phase 3 Round 2 + Phase 10 of Clean Code V12. Ships eight probes that
//! surface architectural drift at the import-graph level:
//!
//! - [`layer_violation`] — downward-only import doctrine; a shallower
//!   layer importing a deeper one is flagged as a layering inversion.
//! - [`circular_import`] — Kahn's-algorithm cycle detection across the
//!   per-batch import graph; every member of a cycle gets a Blocker
//!   finding pointing at its cycle partners via `related`.
//! - [`fan_in_outlier`] — a module with too many incoming imports is a
//!   god hub; threshold defaults to 30.
//! - [`fan_out_outlier`] — a module that imports too many other modules
//!   is a god dispatcher; threshold defaults to 25.
//! - [`ownership_gap`] — STUB. Phase-3 returns no findings; the real
//!   `CODEOWNERS`-driven rule lands in Phase 4.
//!
//! Phase 10 (Batch L — multi-language cross-cutting probes mined from
//! ArchUnit / dependency-cruiser / Sonar layering rules):
//!
//! - [`layer_violation_import`] — domain-layer file imports from
//!   infrastructure-layer module (path-component heuristic).
//! - [`god_module_imports`] — single file declares more than 30
//!   imports.
//! - [`cross_module_private_access`] — Python `from foo._private import
//!   X` style import of a single-underscore-prefixed name.
//!
//! See [`BuiltinArchitecturePack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and the
//! crate forbids `unsafe_code`. The pack is wired into the kernel via
//! `cc-kernel::Kernel::with_default_packs`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod circular_import;
pub mod cross_module_private_access;
pub mod fan_in_outlier;
pub mod fan_out_outlier;
pub mod god_module_imports;
mod helpers;
pub mod layer_violation;
pub mod layer_violation_import;
pub mod ownership_gap;
mod pack;

#[cfg(test)]
mod tests;

pub use pack::BuiltinArchitecturePack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinArchitecturePack::PACK_ID;
