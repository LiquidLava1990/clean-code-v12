//! Persistent baseline — accepted findings keyed by stable
//! [`cc_finding::SuppressKey`].
//!
//! The kernel diffs every run against the baseline so only NEW findings
//! escalate to the developer. Inspired by Semgrep `--baseline-commit`,
//! `detect-secrets` baseline files, and Sonar's "new code period."
//!
//! # File map
//!
//! | Module   | Purpose                                              |
//! |----------|------------------------------------------------------|
//! | `error`  | [`BaselineError`] + [`BaselineResult`]               |
//! | `model`  | [`Baseline`], [`BaselineEntry`], schema constants    |
//! | `repo`   | [`BaselineRepo`] — open / accept / touch / save      |
//! | `diff`   | [`apply`] + [`DiffOutcome`]                          |
//! | `io`     | atomic temp-then-rename writes                       |
//!
//! # Self-host gate
//!
//! Every [`BaselineError`] variant says **what** broke and **how** to
//! fix it. Adding an error without a remediation hint is a regression.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod diff;
pub mod error;
pub mod io;
pub mod model;
pub mod repo;

pub use diff::{apply, DiffOutcome};
pub use error::{BaselineError, BaselineResult};
pub use model::{Baseline, BaselineEntry, SCHEMA_VERSION};
pub use repo::BaselineRepo;
