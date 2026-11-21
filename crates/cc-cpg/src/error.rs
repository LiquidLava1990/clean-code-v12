//! Crate error type.
//!
//! All public APIs return [`CpgResult`]. Errors carry an actionable message
//! describing both *what* went wrong and *how to fix it*.

use thiserror::Error;

/// Convenience alias for `Result<T, CpgError>`.
pub type CpgResult<T> = std::result::Result<T, CpgError>;

/// All errors returned by `cc-cpg` public APIs.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CpgError {
    /// A `NodeBuilder` was finalized without setting its kind.
    ///
    /// Fix: construct the builder with [`crate::NodeBuilder::new`] (or set
    /// the kind via [`crate::NodeBuilder::with_kind`]) before pushing it.
    #[error("node builder is missing required `kind` — call `with_kind(...)` before `build()`")]
    NodeKindMissing,

    /// An edge referenced a node id that the batch never declared.
    ///
    /// Fix: ensure both endpoints are added to the batch via
    /// [`crate::CpgWriteBatch::push_node`] before pushing the edge.
    #[error(
        "edge {kind:?} references unknown node {id:?} — push the node into the batch before \
         the edge"
    )]
    DanglingEdge {
        /// Edge variant.
        kind: crate::EdgeKind,
        /// Missing endpoint.
        id: crate::NodeId,
    },

    /// A required property was missing from a node bag.
    ///
    /// Fix: set the named property via [`crate::NodeBuilder::with_prop`] or
    /// audit the frontend lift step that produced this node.
    #[error("node {node_id:?} ({kind:?}) missing required property `{property}` — {hint}")]
    MissingRequiredProperty {
        /// Owning node.
        node_id: crate::NodeId,
        /// Owning node kind.
        kind: crate::NodeKind,
        /// Property key.
        property: &'static str,
        /// What to do about it.
        hint: &'static str,
    },

    /// A `Sha256` hex string failed to parse.
    ///
    /// Fix: pass exactly 64 lower- or upper-case hex characters (32 bytes).
    #[error("invalid sha256 hex `{input}`: {reason} — expected 64 hex characters")]
    InvalidSha256 {
        /// The offending input (truncated).
        input: String,
        /// Why parsing failed.
        reason: &'static str,
    },

    /// Bincode encoding / decoding failed.
    ///
    /// Fix: check that both producer and consumer link the same `cc-cpg`
    /// version with matching [`crate::SCHEMA_VERSION`].
    #[error("bincode codec error: {0}")]
    Codec(String),

    /// Generic JSON serde error surfaced for tooling.
    ///
    /// Fix: inspect the offending property — `Value::Map` keys must be UTF-8.
    #[error("json codec error: {0}")]
    Json(String),
}

impl From<serde_json::Error> for CpgError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}
