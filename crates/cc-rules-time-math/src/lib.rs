//! `cc-rules-time-math` — Family 14 (time + math) probe pack.
//!
//! Phase 3 of Clean Code V12. Ships five probes addressing the most
//! common money / time / float correctness bugs:
//!
//! - [`naive_datetime`] — `datetime.now()` / constructor without `tz=`.
//! - [`float_equality`] — `==` / `!=` on float-typed operands.
//! - [`money_in_float`] — currency identifiers bound to `float`.
//! - [`dst_unsafe`] — local-time arithmetic across DST boundaries.
//! - [`leap_second`] — timestamp delta divided by seconds-per-unit.
//!
//! See [`BuiltinTimeMathPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`. The pack dogfoods the Tier-0
//! forever rules — no bare `unwrap()` outside tests, every error
//! variant carries an `R-ERR-ACTION` doc string.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod dst_unsafe;
pub mod float_equality;
mod helpers;
pub mod leap_second;
pub mod money_in_float;
pub mod naive_datetime;
mod pack;

#[cfg(test)]
mod tests;

pub use pack::BuiltinTimeMathPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinTimeMathPack::PACK_ID;
