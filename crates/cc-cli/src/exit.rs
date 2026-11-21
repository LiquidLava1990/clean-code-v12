//! [`ExitCode`] — explicit exit-code mapping for the `ccv12` binary.
//!
//! Stable contract:
//!
//! - `0` — clean run, no escalated findings.
//! - `1` — findings present at-or-above the configured severity floor.
//! - `2` — kernel / config / I/O error.
//! - `3` — invalid argv (delegated to `clap` directly via process exit).
//!
//! CI consumers diff against these codes; do **not** renumber.

/// Exit-code classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// No findings escalated. Repo is clean for the configured filter.
    Clean = 0,
    /// At least one finding was emitted at or above the severity floor.
    Findings = 1,
    /// Kernel / config / I/O failure — `ccv12` could not run to completion.
    RuntimeError = 2,
    /// Argv parsing rejected the input. Reserved for `clap` failures.
    InvalidArgv = 3,
}

impl ExitCode {
    /// Numeric exit code for `std::process::exit`.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(value: ExitCode) -> Self {
        // ExitCode supports u8 values; clamp safely via `as`.
        Self::from(value as u8)
    }
}
