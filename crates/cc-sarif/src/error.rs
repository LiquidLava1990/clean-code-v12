//! Errors raised when emitting or validating a SARIF document.
//!
//! Every variant follows the R-ERR-ACTION shape: it states **what** went
//! wrong and tells the caller **how** to fix it.

use thiserror::Error;

/// Errors raised by `to_sarif`, `validate`, and the SARIF sink.
#[derive(Debug, Error)]
pub enum SarifError {
    /// Underlying serde-json failure.
    #[error(
        "SARIF JSON serialisation failed: {source}; \
         verify the SarifDocument has no NaN/inf number fields"
    )]
    Serde {
        /// Underlying serde error.
        #[from]
        source: serde_json::Error,
    },

    /// I/O error while writing the document.
    #[error(
        "SARIF sink I/O failed at `{context}`: {source}; \
         verify the output target is writable and the disk is not full"
    )]
    Io {
        /// Where the I/O happened.
        context: &'static str,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Validation failures detected by [`crate::validate::validate`].
    #[error(
        "SARIF document failed self-validation: {count} issue(s); \
         inspect SarifError::Validation.errors for the per-issue list and \
         fix each before emitting"
    )]
    Validation {
        /// Number of issues collected.
        count: usize,
        /// Detailed per-issue list.
        errors: Vec<SarifValidationError>,
    },
}

/// One self-validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SarifValidationError {
    /// `version` does not equal `"2.1.0"`.
    #[error(
        "SARIF document.version is `{found}`, expected `2.1.0`; \
         set SarifDocument::version to crate::doc::SARIF_VERSION"
    )]
    BadVersion {
        /// What was found.
        found: String,
    },

    /// At least one run is required.
    #[error(
        "SARIF document has zero runs; emit at least one Run with a Tool driver, \
         or skip emitting the document entirely if there are no findings"
    )]
    NoRuns,

    /// Run is missing a tool driver name.
    #[error(
        "SARIF run #{run} has empty tool.driver.name; \
         pass a non-empty ToolMeta::name to to_sarif()"
    )]
    EmptyDriverName {
        /// Index of the offending run.
        run: usize,
    },

    /// Result is missing its rule id.
    #[error(
        "SARIF run #{run} result #{result} has empty ruleId; \
         every Finding must carry a non-empty rule_id before mapping"
    )]
    EmptyRuleId {
        /// Index of the offending run.
        run: usize,
        /// Index of the offending result inside the run.
        result: usize,
    },

    /// Result level is not one of the accepted values.
    #[error(
        "SARIF run #{run} result #{result} has level `{found}` — \
         expected one of: error, warning, note, none; \
         use Severity::sarif_level() to derive the level"
    )]
    BadLevel {
        /// Index of the offending run.
        run: usize,
        /// Index of the offending result inside the run.
        result: usize,
        /// What was found.
        found: String,
    },

    /// Fingerprint is not lowercase hex.
    #[error(
        "SARIF run #{run} result #{result} fingerprint `{key}` value is not lowercase hex \
         (got `{value}`); use SuppressKey::to_hex() which guarantees lowercase output"
    )]
    BadFingerprint {
        /// Index of the offending run.
        run: usize,
        /// Index of the offending result inside the run.
        result: usize,
        /// Fingerprint key.
        key: String,
        /// Offending value.
        value: String,
    },

    /// Result has no locations.
    #[error(
        "SARIF run #{run} result #{result} has zero locations; \
         every result needs at least one physicalLocation pointing at the source range"
    )]
    NoLocations {
        /// Index of the offending run.
        run: usize,
        /// Index of the offending result inside the run.
        result: usize,
    },
}

/// Crate-wide convenience [`Result`] alias.
pub type Result<T> = std::result::Result<T, SarifError>;
