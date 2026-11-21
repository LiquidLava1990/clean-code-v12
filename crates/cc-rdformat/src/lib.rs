//! `RDJSON` (reviewdog JSON) emitter for [`cc_finding::Finding`].
//!
//! `RDJSON` is the line-delimited JSON variant of reviewdog's `RDFormat`
//! family. It is the **transport** format we pipe to `reviewdog -f
//! rdjson` for posting PR review comments. SARIF (in `cc-sarif`) remains
//! the archive of record; this crate is intentionally lossy on
//! `confidence`, `cost`, and `evidence.cpg_node_dump`.
//!
//! # Wire format
//!
//! Each [`cc_finding::Finding`] becomes one JSON object on its own line.
//! The schema lives at
//! <https://github.com/reviewdog/reviewdog/blob/master/proto/rdf/jsonschema/DiagnosticResult.jsonschema>
//! — see [`doc::RdJsonDiagnostic`] for the Rust mirror.
//!
//! # File map
//!
//! | Module        | Purpose                                          |
//! |---------------|--------------------------------------------------|
//! | `error`       | [`RdFormatError`] + crate `Result` alias         |
//! | `doc`         | `RDJSON` document types ([`doc::RdJsonDiagnostic`])|
//! | `to_rdjson`   | [`to_rdjson::to_rdjson`] mapping function        |
//! | `sink`        | [`sink::RdJsonSink`] streaming `FindingSink` impl|
//!
//! # Self-host gate
//!
//! Every error in this crate states **what** failed and **how** to fix
//! it (R-ERR-ACTION dogfood). Adding a new error variant without an
//! actionable message is a regression caught by the
//! `error_messages_are_actionable` test.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod doc;
pub mod error;
pub mod sink;
pub mod to_rdjson;

#[cfg(test)]
mod test_support;

pub use doc::{
    RdCode, RdJsonDiagnostic, RdLocation, RdPosition, RdRange, RdSeverity, RdSource, RdSuggestion,
    SourceMeta,
};
pub use error::{RdFormatError, Result};
pub use sink::RdJsonSink;
pub use to_rdjson::to_rdjson;
