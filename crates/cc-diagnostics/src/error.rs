//! Errors emitted by `cc-diagnostics`.
//!
//! Every variant follows R-ERR-ACTION: it states *what* went wrong
//! and *how* to fix it.

use thiserror::Error;

/// Errors produced when constructing or sinking a [`Diagnostic`].
///
/// [`Diagnostic`]: crate::Diagnostic
#[derive(Debug, Error)]
pub enum DiagnosticsError {
    /// A diagnostic `code` did not match the canonical naming rule.
    #[error(
        "diagnostic code `{code}` is not lower-snake-case dotted; \
         use the form `diag.<subsystem>.<event>` (see docs/diagnostics.md)"
    )]
    InvalidCode {
        /// The offending code string.
        code: String,
    },

    /// A sink failed to accept a diagnostic.
    #[error(
        "diagnostic sink `{sink}` rejected a diagnostic: {reason}; \
         verify the sink target is writable and not closed"
    )]
    SinkFailure {
        /// Sink type-name for triage.
        sink: &'static str,
        /// Why the sink refused the diagnostic.
        reason: String,
    },
}

/// Crate-wide convenience [`Result`] alias.
pub type Result<T> = std::result::Result<T, DiagnosticsError>;
