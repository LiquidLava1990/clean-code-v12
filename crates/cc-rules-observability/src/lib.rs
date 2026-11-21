//! `cc-rules-observability` — Family 11 (observability) probe pack.
//!
//! Phase 4 of Clean Code V12. Ships six probes covering log content,
//! metric quality, PII leakage, and trace propagation gaps. Family 25
//! (`cc-rules-completeness::observe`) covers structural tracer presence;
//! this crate covers the *content* and *quality* axes that family does
//! not — silent catches, missing metrics around external I/O,
//! unstructured log calls, high-cardinality metric labels, RPCs without
//! correlation context, and PII embedded in log format strings.
//!
//! Probes:
//!
//! - [`silent_catch`] — exception logged then swallowed.
//! - [`missing_metrics`] — public function with external I/O but no
//!   metric primitive.
//! - [`unstructured_log`] — log call whose only arg is a literal string.
//! - [`high_cardinality_label`] — metric with a user/request/session id
//!   in the label set.
//! - [`no_correlation_id`] — outbound HTTP call inside a function with
//!   no surrounding tracing/span macro.
//! - [`pii_in_log`] — log format string containing PII keywords.
//!
//! See [`BuiltinObservabilityPack`] for the registered
//! [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and the
//! crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod helpers;
pub mod high_cardinality_label;
pub mod missing_metrics;
pub mod no_correlation_id;
mod pack;
pub mod pii_in_log;
pub mod silent_catch;
pub mod unstructured_log;

#[cfg(test)]
mod tests;

pub use pack::BuiltinObservabilityPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinObservabilityPack::PACK_ID;
