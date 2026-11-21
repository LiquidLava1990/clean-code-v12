//! `cc-cli` — Phase-1 user-facing binary for Clean Code V12.
//!
//! The library half exposes [`run`], [`run_check`], [`run_init`], and
//! the type surface the binary stitches together. It exists so end-to-end
//! tests can drive the CLI without forking a child process.
//!
//! # Forever rules atop
//!
//! - File ≤1500 LOC, function ≤50 LOC, nesting ≤3.
//! - No bare `unwrap()`/`expect()` outside tests.
//! - `R-ERR-ACTION` dogfood — every [`CliError`] variant says *what*
//!   went wrong **and** *how* to fix it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod args;
pub mod baseline;
pub mod error;
pub mod exit;
pub mod fix;
pub mod format;
pub mod harness;
pub mod runner;

pub use args::{
    BaselineArgs, BaselineClearArgs, BaselineCmd, BaselineCreateArgs, BaselineStatusArgs,
    BaselineSyncArgs, CheckArgs, Cli, Cmd, FixArgs, HarnessArgs, HarnessCmd, HarnessInitArgs,
    HarnessRegenerateArgs, HarnessVerifyArgs, InitArgs, OutputFormat, SeverityFilter,
};
pub use baseline::{
    run_baseline, run_baseline_clear, run_baseline_create, run_baseline_status, run_baseline_sync,
    BaselineStatus, DEFAULT_BASELINE_FILE,
};
pub use error::{CliError, Result};
pub use exit::ExitCode;
pub use fix::run_fix;
pub use format::{sink_for, JsonLinesSink};
pub use harness::{run_harness, run_harness_init, run_harness_regenerate, run_harness_verify};
pub use runner::{run, run_check, run_init};
