//! Crate error type.
//!
//! Every variant carries both *what* broke and *how* to fix it (R-ERR-ACTION).

use thiserror::Error;

/// Convenience alias for `Result<T, FingerprintError>`.
pub type FingerprintResult<T> = std::result::Result<T, FingerprintError>;

/// All errors returned by `cc-fingerprint` public APIs.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FingerprintError {
    /// A node carrying a name (Function/Class/Variable/Parameter/Module)
    /// was missing the canonical `name` string property.
    ///
    /// Fix: ensure the lifting frontend sets `name: Value::String(...)` on
    /// the node before flushing the batch into [`crate::FingerprintBuilder`].
    #[error(
        "node id={node_id} kind={kind} is missing required `name` string property — \
         set it via `NodeBuilder::with_prop(\"name\", Value::String(..))` in the frontend lift step"
    )]
    MissingName {
        /// Raw node id (`NodeId::get`).
        node_id: u64,
        /// Stable string tag of the node kind that produced the failure.
        kind: &'static str,
    },

    /// An import or module node referenced an unknown target path.
    ///
    /// Fix: ensure the frontend resolver has populated the `target` /
    /// `module_path` property for `Import` nodes before lifting, or skip
    /// unresolved imports in the frontend rather than emitting them
    /// half-formed.
    #[error(
        "import edge from `{from}` references missing target — populate the `target` property \
         on the Import node, or drop unresolved imports at lift time"
    )]
    DanglingImport {
        /// Source module path of the import.
        from: String,
    },

    /// A property held the wrong [`cc_cpg::Value`] tag.
    ///
    /// Fix: audit the frontend lift step — the documented schema for this
    /// property requires the named tag.
    #[error(
        "node id={node_id} property `{property}` has tag `{actual_tag}`, expected `{expected_tag}` \
         — audit the frontend lift step that wrote this property"
    )]
    WrongPropertyTag {
        /// Raw node id.
        node_id: u64,
        /// Property key.
        property: &'static str,
        /// What we expected.
        expected_tag: &'static str,
        /// What we found.
        actual_tag: &'static str,
    },
}
