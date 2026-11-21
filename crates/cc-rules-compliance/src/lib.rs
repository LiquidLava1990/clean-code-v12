//! `cc-rules-compliance` — Family 21 (compliance) probe pack.
//!
//! Phase 5 of Clean Code V12. Ships four probes:
//!
//! - [`pii_handling`] — PII-named field without an encryption-at-rest hint.
//! - [`gdpr_pattern`] — user-data class missing export / forget / delete /
//!   anonymize methods. Phase-5 STUB pending whole-class method-set
//!   comparison.
//! - [`audit_log_gap`] — privileged operation function with no audit-log
//!   call in its body.
//! - [`license_violation`] — GPL-bearing `LICENSE` file alongside a
//!   non-GPL top-level `LICENSE`.
//!
//! See [`BuiltinCompliancePack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod audit_log_gap;
pub mod gdpr_pattern;
mod helpers;
pub mod license_violation;
mod pack;
pub mod pii_handling;

#[cfg(test)]
mod tests;

pub use pack::BuiltinCompliancePack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinCompliancePack::PACK_ID;
