//! Errors emitted by the `cc-finding` crate.
//!
//! Every variant follows the R-ERR-ACTION shape: it states **what** went
//! wrong and tells the caller **how** to fix it.

use thiserror::Error;

/// Errors raised when constructing, serialising or sinking a [`Finding`].
///
/// [`Finding`]: crate::Finding
#[derive(Debug, Error)]
pub enum FindingError {
    /// A required builder field was missing at `.build()` time.
    #[error(
        "missing required field `{field}` on FindingBuilder; \
         call `.{field}(...)` before `.build()`"
    )]
    MissingField {
        /// Name of the missing field.
        field: &'static str,
    },

    /// A field's value is outside its accepted domain.
    #[error(
        "field `{field}` has invalid value: {reason}; \
         consult docs/finding-schema.md for the accepted range"
    )]
    InvalidValue {
        /// Name of the offending field.
        field: &'static str,
        /// Why the value was rejected.
        reason: String,
    },

    /// JSON (de)serialisation failed.
    #[error(
        "JSON (de)serialisation failed for Finding: {source}; \
         verify the schema_version matches the producer"
    )]
    Serde {
        /// Underlying serde error.
        #[from]
        source: serde_json::Error,
    },

    /// I/O failure inside a [`FindingSink`].
    ///
    /// [`FindingSink`]: crate::FindingSink
    #[error(
        "sink I/O failed at `{context}`: {source}; \
         verify the sink target is writable and not full"
    )]
    Io {
        /// Where the I/O happened.
        context: &'static str,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Severity could not be parsed from string.
    #[error(
        "could not parse Severity from `{input}`; \
         expected one of: blocker, required, nit"
    )]
    UnknownSeverity {
        /// The unrecognised input.
        input: String,
    },
}

/// Crate-wide convenience [`Result`] alias.
pub type Result<T> = std::result::Result<T, FindingError>;
