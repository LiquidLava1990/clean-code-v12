//! `cc-rules-memory` — Family 6 (memory / leaks) probe pack.
//!
//! Phase 3 Round 2 of Clean Code V12. Ships five probes:
//!
//! - [`unclosed_resource`] — file / socket / cursor opened without
//!   matching `close()` / `with` / `defer` / try-with-resources.
//! - [`use_after_free`] — STUB. Real port lands in Phase 4 once the
//!   Infer Pulse adapter is wired.
//! - [`double_free`] — STUB. Same Phase-4 wiring as `use_after_free`.
//! - [`event_loop_leak`] — async spawn handles whose result is never
//!   awaited / cancelled / cleared.
//! - [`cache_unbounded`] — module / class scope dict / list / map / vec
//!   with insert-style calls but no remove-style calls.
//!
//! See [`BuiltinMemoryPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cache_unbounded;
pub mod double_free;
pub mod event_loop_leak;
mod helpers;
mod pack;
pub mod unclosed_resource;
pub mod use_after_free;

#[cfg(test)]
mod tests;

pub use pack::BuiltinMemoryPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinMemoryPack::PACK_ID;
