//! `cc-rules-formatting` — Family 26 (formatting drift) probe pack.
//!
//! Phase 6 of Clean Code V12. Adoption-friendly: every probe defaults
//! to [`cc_finding::Severity::Nit`] so wiring the pack into a repo
//! never raises the Required/Blocker count. Ten probes cover the
//! file-bytes-level formatting drift that V12's structural Tier-0
//! pack does not see — quotation style, trailing whitespace, tab/space
//! mixing, line endings, BOMs, line length, TODO ownership, etc.
//!
//! The OSS-linter delta study flagged ~150
//! formatting rules in ruff `Q*` + ESLint stylistic + clippy style +
//! gofumpt + black. Most are auto-fixable but V12 doesn't even detect
//! them yet — this pack closes the detection gap. Auto-fix is left to
//! a later phase.
//!
//! - [`trailing_whitespace`] — line ending in spaces/tabs before `\n`.
//! - [`mixed_indentation`] — file mixes tab- and space-indented lines.
//! - [`tab_in_python`] — `*.py` file using tab indentation.
//! - [`crlf_line_endings`] — `\r\n` in source files (per-repo digest).
//! - [`bom_present`] — file starts with the UTF-8 BOM.
//! - [`no_final_newline`] — file does not end with a newline.
//! - [`multiple_blank_lines`] — > 2 consecutive blank lines.
//! - [`inconsistent_string_quotes`] — Python/JS/TS file mixing `'`/`"`.
//! - [`long_line`] — line > 120 chars (URLs/paths/regexes whitelisted).
//! - [`todo_no_owner`] — `TODO:` without owner attribution.
//!
//! See [`BuiltinFormattingPack`] for the registered
//! [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bom_present;
pub mod crlf_line_endings;
mod helpers;
pub mod inconsistent_string_quotes;
pub mod long_line;
pub mod mixed_indentation;
pub mod multiple_blank_lines;
pub mod no_final_newline;
mod pack;
pub mod tab_in_python;
pub mod todo_no_owner;
pub mod trailing_whitespace;

#[cfg(test)]
mod tests;

pub use pack::BuiltinFormattingPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinFormattingPack::PACK_ID;
