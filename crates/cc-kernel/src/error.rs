//! [`KernelError`] — the orchestrator's error surface.
//!
//! Every variant follows R-ERR-ACTION: it states *what* failed and *how*
//! to fix it. The kernel never panics on user input; everything routes
//! through this enum.

use camino::Utf8PathBuf;
use thiserror::Error;

/// Result alias for kernel operations.
pub type KernelResult<T> = Result<T, KernelError>;

/// All errors surfaced by the kernel orchestrator.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KernelError {
    /// Failure while validating or interpreting the loaded `Config`.
    #[error(
        "kernel config error: {reason} — \
         re-run after correcting `.cc/config.toml` (see `ccv12 init` for a \
         valid template)"
    )]
    Config {
        /// Human-readable reason naming the offending field.
        reason: String,
    },

    /// A globset compiled from `cc-config` rejected at kernel startup.
    #[error(
        "kernel could not compile path-scope globs in {field}: {source} — \
         fix the offending pattern under `.cc/config.toml` and re-run"
    )]
    GlobCompile {
        /// Field name that produced the bad pattern.
        field: String,
        /// Underlying config error wrapped for context.
        #[source]
        source: cc_config::ConfigError,
    },

    /// Failure registering a [`cc_rules::RulePack`] with the registry.
    #[error(
        "kernel could not register rule pack: {source} — \
         verify the pack's kernel_api_min/max window matches this kernel \
         and that no other pack already owns the same pack_id"
    )]
    Registry {
        /// Underlying rule-registry error.
        #[source]
        source: cc_rules::RegistryError,
    },

    /// A frontend failed to parse-and-lift a file in a way that should
    /// abort the run (rare; most failures are demoted to `tracing::warn`
    /// and skipped). Reserved for future use.
    #[error(
        "frontend pipeline failed for {path}: {source} — \
         file an issue against the responsible language frontend with \
         this path and the error message"
    )]
    Frontend {
        /// Repo-relative path that failed.
        path: Utf8PathBuf,
        /// Underlying frontend error.
        #[source]
        source: cc_frontend::FrontendError,
    },

    /// Filesystem error reading a source file.
    #[error(
        "kernel could not read {path}: {source} — \
         verify the file exists, is UTF-8 encoded, and the current process \
         has read permission"
    )]
    Io {
        /// Path that failed to read.
        path: Utf8PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Sink emission failure.
    #[error(
        "kernel sink failed at {context}: {source} — \
         verify the sink target is writable; baseline / tty / sarif sinks \
         each surface this differently"
    )]
    Sink {
        /// Where the I/O happened (e.g. `"emit_finding"`).
        context: &'static str,
        /// Underlying finding sink error.
        #[source]
        source: cc_finding::FindingError,
    },
}

impl From<cc_rules::RegistryError> for KernelError {
    fn from(source: cc_rules::RegistryError) -> Self {
        Self::Registry { source }
    }
}
