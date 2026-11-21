//! `cc-kernel` — Clean Code V12 orchestration crate.
//!
//! The kernel is what `ccv12 check` invokes: walk the repo, parse + lift
//! every supported file, run every registered rule, score the result,
//! emit findings to a sink, and return a structured report.
//!
//! # Architecture
//!
//! ```text
//!                +---------------------------+
//!                |        Kernel::run        |
//!                +-------------+-------------+
//!                              |
//!                  walker (`ignore` + globset)
//!                              |
//!                  rayon parallel parse+lift
//!                              |
//!              CpgWriteBatch per supported file
//!                              |
//!     for each (batch, path):  for each Rule in registry:
//!                  cc_rules::run_rule(rule, ctx)  ----> Vec<Finding>
//!                              |
//!                  cc_score::ScoreEngine::score
//!                              |
//!              Vec<Finding>  +  HealthScore
//!                              |
//!                  emit -> &mut dyn FindingSink
//!                              |
//!                       KernelRunReport
//! ```
//!
//! # Public surface
//!
//! - [`Kernel`] — the orchestrator.
//! - [`KernelError`] / [`KernelResult`] — actionable error type +
//!   alias.
//! - [`KernelRunReport`] — the structured outcome of a single run.
//! - [`PerRuleTiming`] — `BTreeMap<rule_id, Duration>` aggregation.
//! - [`walk_repo`] — exposed for ad-hoc tooling that wants the same
//!   ignore semantics without booting a full kernel.
//! - [`frontend_for_path`] / [`is_supported_extension`] — language
//!   dispatch helpers.
//!
//! # Forever rules atop
//!
//! - File ≤1500 LOC, function ≤50 LOC, nesting ≤3.
//! - No bare `unwrap()`/`expect()` outside tests.
//! - Every public surface carries doc comments.
//! - Concurrency: rayon for the file fan-out only; no ad-hoc threads.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod language;
mod report;
mod runner;
mod walker;

pub use error::{KernelError, KernelResult};
pub use language::{extension_is_tsx, frontend_for_path, is_supported_extension};
pub use report::{KernelRunReport, PerRuleTiming};
pub use runner::Kernel;
pub use walker::{walk_repo, WalkOutcome, DEFAULT_MAX_FILE_BYTES};

#[cfg(test)]
mod tests;
