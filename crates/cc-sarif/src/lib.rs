//! SARIF 2.1.0 emitter for `cc-finding::Finding`.
//!
//! cc-sarif consumes a slice of [`cc_finding::Finding`] and produces a
//! valid SARIF 2.1.0 JSON document. The output is designed to pass
//! GitHub code-scanning ingestion + microsoft/sarif-tools `validate`.
//!
//! # Surface
//!
//! - [`to_sarif`] — pure mapping function: findings + [`ToolMeta`] →
//!   [`SarifDocument`].
//! - [`SarifSink`] — `FindingSink` impl that buffers findings and emits
//!   one document on `finish()`.
//! - [`validate`] — self-sanity validator (required fields, level enum,
//!   fingerprint hex format).
//!
//! Schema-level conformance (full JSON-schema validation) is the
//! consumer's responsibility — `microsoft/sarif-multitool validate` is
//! the canonical check.
//!
//! # File map
//!
//! | Module      | Purpose                                                  |
//! |-------------|----------------------------------------------------------|
//! | `doc`       | SARIF document model (`SarifDocument` + nested types)    |
//! | `to_sarif`  | `Finding` → `SarifResult` mapping + [`ToolMeta`]         |
//! | `sink`      | `SarifSink` (`FindingSink` impl) + `OutputMode`          |
//! | `validate`  | Self-sanity validator                                    |
//! | `error`     | `SarifError` + `SarifValidationError`                    |

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod doc;
pub mod error;
pub mod sink;
pub mod to_sarif;
pub mod validate;

pub use doc::{
    ArtifactChange, ArtifactContent, ArtifactLocation, Fix, Invocation, Location, Message,
    MultiformatMessageString, PhysicalLocation, Region, Replacement, ReportingConfiguration,
    ReportingDescriptor, Run, SarifDocument, SarifResult, Tool, ToolComponent, SARIF_SCHEMA_URI,
    SARIF_VERSION,
};
pub use error::{Result, SarifError, SarifValidationError};
pub use sink::{OutputMode, SarifSink};
pub use to_sarif::{to_sarif, ToolMeta};
pub use validate::validate;
