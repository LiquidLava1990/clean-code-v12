//! [`CliError`] — actionable error surface for the `cc` binary.
//!
//! Every variant follows the R-ERR-ACTION dogfood: it states **what**
//! went wrong and **how** the operator should fix it.

use camino::Utf8PathBuf;
use thiserror::Error;

/// Crate-wide alias.
pub type Result<T> = std::result::Result<T, CliError>;

/// Errors surfaced by the `cc` binary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CliError {
    /// The supplied repo root does not exist or is not a directory.
    #[error(
        "repo root `{path}` is not a directory — \
         pass an existing directory or run `cc init <PATH>` first"
    )]
    InvalidRoot {
        /// The path that failed validation.
        path: Utf8PathBuf,
    },

    /// `.cc/config.toml` already exists during `cc init` without `--force`.
    #[error(
        "config already exists at `{path}` — \
         re-run `cc init --force` to overwrite, or edit the file in place"
    )]
    ConfigExists {
        /// Path of the existing config.
        path: Utf8PathBuf,
    },

    /// The `--output` target could not be created.
    #[error(
        "could not create output file `{path}`: {source} — \
         verify the parent directory exists and is writable"
    )]
    OutputCreate {
        /// Output path that failed creation.
        path: Utf8PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// `cc-config` rejected the loaded `.cc/config.toml`.
    #[error(
        "config error: {source} — \
         fix `.cc/config.toml` and re-run; `cc init --force` regenerates a valid template"
    )]
    Config {
        /// Underlying config error.
        #[source]
        source: cc_config::ConfigError,
    },

    /// `cc-kernel` failed during the run.
    #[error(
        "kernel error: {source} — \
         see the message above for the offending file/rule and remediation"
    )]
    Kernel {
        /// Underlying kernel error.
        #[source]
        source: cc_kernel::KernelError,
    },

    /// The configured sink rejected `finish()`.
    #[error(
        "sink finalisation failed: {source} — \
         verify the output target is writable and not full"
    )]
    SinkFinish {
        /// Underlying finding error.
        #[source]
        source: cc_finding::FindingError,
    },

    /// Baseline file could not be loaded or parsed.
    #[error(
        "baseline error at `{path}`: {source} — \
         re-run `cc init` to regenerate, or fix the JSON manually"
    )]
    Baseline {
        /// Path of the baseline file.
        path: Utf8PathBuf,
        /// Underlying baseline error.
        #[source]
        source: cc_baseline::BaselineError,
    },

    /// Generic I/O failure during init.
    #[error(
        "I/O failed at `{context}`: {source} — \
         verify the path exists and the current process has the required permissions"
    )]
    Io {
        /// Where the I/O happened.
        context: &'static str,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// `cc harness` could not complete its scaffold / verify / regenerate run.
    #[error("{message} — {action}")]
    Harness {
        /// What broke (filled by the harness handler).
        message: String,
        /// Static remediation hint shown after the message.
        action: &'static str,
    },
}

impl From<cc_config::ConfigError> for CliError {
    fn from(source: cc_config::ConfigError) -> Self {
        Self::Config { source }
    }
}

impl From<cc_kernel::KernelError> for CliError {
    fn from(source: cc_kernel::KernelError) -> Self {
        Self::Kernel { source }
    }
}
