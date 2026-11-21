//! `cc-rules-docs` — Family 16 (documentation) probe pack.
//!
//! Phases 5 + 10 of Clean Code V12. Ships eight probes:
//!
//! Phase 5 (original five):
//!
//! - [`readme_install_broken`] — STUB; needs runme-style command
//!   execution (Phase 6).
//! - [`docstring_signature_drift`] — REAL: compares the parameter list
//!   declared inside a Python-style `:param x:` docstring against the
//!   function's actual [`cc_cpg::NodeKind::Parameter`] children and
//!   flags any mismatch.
//! - [`docstring_coverage`] — REAL: flags public-visibility functions
//!   that have no preceding `///` / `#` / `/**` doc-comment within
//!   three source lines.
//! - [`dead_link`] — STUB; needs an HTTP fetcher (Phase 6).
//! - [`example_doesnt_compile`] — STUB; needs sub-process `mdbook test`
//!   plumbing (Phase 6).
//!
//! Phase 10 (Python long-tail mined from ruff D-family):
//!
//! - [`docstring_first_line_period`] — first line missing `.`/`!`/`?`
//!   terminator (ruff D400).
//! - [`docstring_first_line_imperative`] — first word reads as
//!   third-person rather than imperative (ruff D401).
//! - [`docstring_summary_blank_line`] — multi-line docstring without a
//!   blank line between summary and body (ruff D205).
//!
//! See [`BuiltinDocsPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod dead_link;
pub mod docstring_coverage;
pub mod docstring_first_line_imperative;
pub mod docstring_first_line_period;
pub mod docstring_signature_drift;
pub mod docstring_summary_blank_line;
pub mod example_doesnt_compile;
mod helpers;
mod pack;
pub mod readme_install_broken;

#[cfg(test)]
mod tests;

pub use pack::BuiltinDocsPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinDocsPack::PACK_ID;
