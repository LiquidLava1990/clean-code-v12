//! Error surface for the incremental layer.
//!
//! Boundary errors (filesystem I/O during the watcher loop, missing files,
//! frontend parse failures) are carried by [`IncrementalError`]. Internal
//! salsa caching never errors — it either returns a cached value or
//! recomputes — so this enum is intentionally small.

use std::io;

use camino::Utf8PathBuf;
use thiserror::Error;

/// Result alias used throughout `cc-incremental`.
pub type IncrementalResult<T> = Result<T, IncrementalError>;

/// Boundary errors produced by the incremental layer.
///
/// Per S2 (granular errors at every call boundary): every variant names
/// what broke + how to act. Use [`IncrementalError::error_code`] for the
/// stable string (taxonomy: `cc-inc.<area>.<reason>`).
#[derive(Debug, Error)]
pub enum IncrementalError {
    /// Filesystem read failed while resolving file content for hashing.
    #[error(
        "cc-inc.io.read_failed: failed to read {path} for incremental hashing \
         (kind={kind:?}); verify the file exists and is readable, then retry"
    )]
    Io {
        /// Repo-relative path that failed to read.
        path: Utf8PathBuf,
        /// IO error kind (no full message — see S10 R-05).
        kind: io::ErrorKind,
    },

    /// File-watcher subsystem failed to start or operate.
    #[error(
        "cc-inc.watcher.{stage}: {detail}; \
         confirm the watch root exists and the process has read permission"
    )]
    Watcher {
        /// Stage name (`start`, `event`, `shutdown`).
        stage: &'static str,
        /// Short, R-05-safe detail (no foreign Debug formatting).
        detail: String,
    },

    /// A file referenced by a query is no longer registered with the database.
    #[error(
        "cc-inc.lookup.unknown_file: file_input id {file_id} is not registered; \
         call CcDatabase::add_file before querying, or re-register if it was removed"
    )]
    UnknownFile {
        /// Numeric salsa id surfaced for diagnostics.
        file_id: u64,
    },
}

impl IncrementalError {
    /// Stable error-code string. Used by SARIF / RDFormat exporters.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "cc-inc.io.read_failed",
            Self::Watcher { .. } => "cc-inc.watcher",
            Self::UnknownFile { .. } => "cc-inc.lookup.unknown_file",
        }
    }
}

impl IncrementalError {
    /// Construct an [`IncrementalError::Io`] from a path + std::io::Error.
    ///
    /// We deliberately drop the full IO message (S10 R-05 — never `repr` a
    /// foreign error containing untrusted bytes); only the `ErrorKind`
    /// classification is propagated.
    #[must_use]
    pub fn io(path: impl Into<Utf8PathBuf>, err: &io::Error) -> Self {
        Self::Io {
            path: path.into(),
            kind: err.kind(),
        }
    }

    /// Construct an [`IncrementalError::Watcher`] from a stage + detail.
    #[must_use]
    pub fn watcher(stage: &'static str, detail: impl Into<String>) -> Self {
        Self::Watcher {
            stage,
            detail: detail.into(),
        }
    }
}
