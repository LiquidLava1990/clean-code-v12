//! `cc-rules-ops` — Family 12 (operations / runtime hygiene) probe pack.
//!
//! Phase 4 of Clean Code V12. Ships seven probes covering operational
//! hygiene axes the completeness decoration probes do not cover:
//!
//! - [`missing_timeout`] — network call without explicit timeout.
//! - [`retry_no_backoff`] — retry loop with constant interval.
//! - [`no_circuit_breaker`] — external dep call without circuit breaker.
//! - [`unbounded_queue`] — producer/consumer without max size.
//! - [`unbounded_memory`] — accumulator without cap (Phase-4 STUB —
//!   defers to `cc.memory.cache_unbounded` in Family 6).
//! - [`no_rate_limit`] — external API call without throttle.
//! - [`infinite_recursion`] — self-recursive function with no base case
//!   (Phase-4 STUB — needs `PDG_DATA`).
//!
//! See [`BuiltinOpsPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and the
//! crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod helpers;
pub mod infinite_recursion;
pub mod missing_timeout;
pub mod no_circuit_breaker;
pub mod no_rate_limit;
mod pack;
pub mod retry_no_backoff;
pub mod unbounded_memory;
pub mod unbounded_queue;

#[cfg(test)]
mod tests;

pub use pack::BuiltinOpsPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinOpsPack::PACK_ID;
