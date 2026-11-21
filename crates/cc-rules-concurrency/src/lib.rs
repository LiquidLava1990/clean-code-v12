//! `cc-rules-concurrency` — Family 5 (concurrency) probe pack.
//!
//! Phases 3 + 7 + 9 of Clean Code V12. Ships eight probes.
//!
//! Phase 3 (original four):
//!
//! - [`race`] — shared mutable state mutated under async / spawn without
//!   a surrounding `Mutex` / `RwLock` / `with_lock` guard.
//! - [`lock_inversion`] — two functions that acquire overlapping locks in
//!   different orders (cycle-risk for deadlock).
//! - [`leaked_task`] — `asyncio.create_task` / `tokio::spawn` /
//!   `setTimeout` whose return value is discarded and whose body is
//!   never awaited.
//! - [`toctou`] — check-then-use across a syscall boundary
//!   (`os.path.exists(p)` followed by `open(p)` in the same function).
//!
//! Phase 7 (Batch E — concurrency probes mined from the OSS delta study):
//!
//! - [`waitgroup_add_in_goroutine`] — Go `wg.Add(1)` inside a `go func()`.
//! - [`signal_unbuffered`] — `signal.Notify` on a `make(chan os.Signal)`
//!   without a buffer.
//!
//! Phase 9 (Batch K — Go-deep-dive probes mined from golangci):
//!
//! - [`context_no_propagate`] — fn already accepting `ctx
//!   context.Context` calls children with `context.Background()` /
//!   `context.TODO()` (golangci `contextcheck`).
//! - [`copy_loop_var`] — `for _, v := range items { go func() { use(v) }() }`
//!   capturing the loop var by reference (golangci `copyloopvar`).
//!
//! See [`BuiltinConcurrencyPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and the
//! crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod context_no_propagate;
pub mod copy_loop_var;
mod helpers;
pub mod leaked_task;
pub mod lock_inversion;
mod pack;
pub mod race;
pub mod signal_unbuffered;
pub mod toctou;
pub mod waitgroup_add_in_goroutine;

#[cfg(test)]
mod tests;

pub use pack::BuiltinConcurrencyPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinConcurrencyPack::PACK_ID;
