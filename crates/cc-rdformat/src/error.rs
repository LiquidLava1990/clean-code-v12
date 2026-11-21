//! Errors emitted by the `cc-rdformat` crate.
//!
//! Every variant follows R-ERR-ACTION: each message states **what** went
//! wrong and tells the caller **how** to remediate.

use thiserror::Error;

/// Errors produced while mapping or streaming `RDJSON` diagnostics.
#[derive(Debug, Error)]
pub enum RdFormatError {
    /// JSON serialisation of an [`crate::doc::RdJsonDiagnostic`] failed.
    #[error(
        "RDJSON serialisation failed: {source}; \
         verify the diagnostic was constructed via `to_rdjson` \
         (custom shapes are not supported)"
    )]
    Serde {
        /// Underlying serde error.
        #[from]
        source: serde_json::Error,
    },

    /// Writing to the configured sink target failed.
    #[error(
        "RDJSON sink write failed at `{context}`: {source}; \
         confirm the sink target is writable and not full"
    )]
    Io {
        /// Operation context — which method was writing.
        context: &'static str,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Bridge from `cc-finding` propagating up through the trait.
    #[error("upstream cc-finding error: {0}; consult the inner error for remediation")]
    Finding(#[from] cc_finding::FindingError),
}

/// Convenience [`Result`] alias used throughout the crate.
pub type Result<T> = std::result::Result<T, RdFormatError>;

impl From<RdFormatError> for cc_finding::FindingError {
    fn from(err: RdFormatError) -> Self {
        match err {
            RdFormatError::Finding(inner) => inner,
            RdFormatError::Serde { source } => Self::Serde { source },
            RdFormatError::Io { context, source } => Self::Io { context, source },
        }
    }
}
