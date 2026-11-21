//! Error types for `cc-test-fixtures`.
//!
//! Every variant carries an actionable message describing both what
//! happened and what the caller should do (see workspace S2 / R-ERR-ACTION).

use camino::Utf8PathBuf;

/// Errors raised by `cc-test-fixtures` operations.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// A fixture file could not be created on disk.
    ///
    /// Recovery: ensure the destination root exists and is writable, then
    /// retry. Inspect [`FixtureError::Write::source`] for the underlying
    /// io error.
    #[error(
        "failed to write fixture to disk path={path}; ensure the destination root exists \
         and is writable, then retry: {source}"
    )]
    Write {
        /// The fixture path that failed to write.
        path: Utf8PathBuf,
        /// Underlying io error.
        #[source]
        source: std::io::Error,
    },

    /// Could not create a parent directory while materialising fixtures.
    ///
    /// Recovery: confirm the supplied root directory permits subdirectory
    /// creation, then retry.
    #[error(
        "failed to create fixture parent dir path={path}; confirm the supplied root \
         permits subdirectory creation, then retry: {source}"
    )]
    Mkdir {
        /// The directory path that failed to create.
        path: Utf8PathBuf,
        /// Underlying io error.
        #[source]
        source: std::io::Error,
    },
}
