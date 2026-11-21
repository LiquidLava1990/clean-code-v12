//! `cc-rules-i18n-a11y` — Family 15 (internationalisation + accessibility).
//!
//! Phase 5 of Clean Code V12. Ships five probes:
//!
//! - [`hardcoded_locale`] — locale string baked into source.
//! - [`unicode_unsafe_op`] — byte-level / count-by-char ops on a string.
//! - [`missing_alt`] — `<img>` / `<image>` JSX tag without an `alt=` prop.
//! - [`color_only_signal`] — error / state communicated by colour alone.
//! - [`keyboard_trap`] — focus trap without an escape route (Phase-5 stub).
//!
//! See [`BuiltinI18nA11yPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod color_only_signal;
pub mod hardcoded_locale;
mod helpers;
pub mod keyboard_trap;
pub mod missing_alt;
mod pack;
pub mod unicode_unsafe_op;

#[cfg(test)]
mod tests;

pub use pack::BuiltinI18nA11yPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinI18nA11yPack::PACK_ID;
