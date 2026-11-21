//! `cc-rules-conventions` — Family 24 (project layout conventions) probe pack.
//!
//! Phase 3 Round 2 of Clean Code V12. Enforces the conventions of a
//! modular service layout rooted at a `platform/` directory: one boot
//! path, per-module manifests, typed events, auth-only `config.json`,
//! and claimed writes to the shared `data/` tree. Codebases without a
//! `platform/` tree are unaffected — files outside it are skipped, so
//! the pack is opt-in by layout and yields zero false positives elsewhere.
//!
//! Five probes ship:
//!
//! - [`config_json_for_non_auth`] — auth-only config: `config.json` may
//!   only carry OAuth / auth values; non-auth keys belong in YAML.
//! - [`startup_py_exists`] — single boot path: no `startup.py`; the
//!   canonical entry point is `platform/main.py`.
//! - [`module_missing_manifest`] — every module under
//!   `platform/modules/<name>/` must have a `__manifest__.py` manifest.
//! - [`untyped_event`] — events emitted via the
//!   EventBus must come from a typed contract — never an inline
//!   string literal.
//! - [`file_claim_bypass`] — writes under
//!   `data/` must go through `FileClaimRegistry::sync_claim_scope`.
//!
//! See [`BuiltinConventionsPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`. The kernel itself has no `platform/`
//! tree — running `ccv12` against this workspace returns zero findings
//! from this pack by design (every probe checks `is_layout_path`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config_json_for_non_auth;
pub mod file_claim_bypass;
mod helpers;
pub mod module_missing_manifest;
mod pack;
pub mod startup_py_exists;
pub mod untyped_event;

#[cfg(test)]
mod tests;

pub use pack::BuiltinConventionsPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinConventionsPack::PACK_ID;
