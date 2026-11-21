//! Errors emitted by `cc-baseline`.
//!
//! Every variant follows the R-ERR-ACTION shape: it states **what** went
//! wrong and tells the caller **how** to fix it.

use camino::Utf8PathBuf;
use thiserror::Error;

/// Errors raised when reading, writing or diffing a baseline file.
#[derive(Debug, Error)]
pub enum BaselineError {
    /// Failed to read the on-disk baseline file.
    #[error(
        "failed to read baseline at `{path}`: {source}; \
         verify the file exists and the process has read permission, \
         or pass a different `--baseline-path`"
    )]
    Read {
        /// Path the kernel attempted to read.
        path: Utf8PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to write the on-disk baseline file.
    #[error(
        "failed to write baseline at `{path}`: {source}; \
         verify the parent directory exists and is writable, \
         and that no other process holds the file open"
    )]
    Write {
        /// Path the kernel attempted to write.
        path: Utf8PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Atomic-write rename step failed after the temp file was flushed.
    #[error(
        "atomic rename failed for baseline `{path}`: {source}; \
         the temp file `{tmp}` may still be on disk — \
         remove it manually if it persists"
    )]
    Rename {
        /// Final destination path.
        path: Utf8PathBuf,
        /// Temp file that was being promoted.
        tmp: Utf8PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// JSON (de)serialisation failed.
    #[error(
        "JSON (de)serialisation failed for baseline at `{path}`: {source}; \
         verify `schema_version` matches the kernel \
         (run `ccv12 baseline migrate` if it lags)"
    )]
    Serde {
        /// Path the kernel was (de)serialising.
        path: Utf8PathBuf,
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// Schema version on disk is newer/unsupported.
    #[error(
        "baseline at `{path}` has schema_version {found}, \
         this kernel supports up to {supported}; \
         upgrade the kernel or regenerate the baseline with `ccv12 baseline create`"
    )]
    UnsupportedSchema {
        /// Path the kernel was reading.
        path: Utf8PathBuf,
        /// Version stored on disk.
        found: u32,
        /// Highest version this kernel understands.
        supported: u32,
    },
}

/// Crate-wide convenience [`Result`] alias.
pub type BaselineResult<T> = std::result::Result<T, BaselineError>;
