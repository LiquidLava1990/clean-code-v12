//! Source-code anchors: [`Location`], [`Position`], [`RelatedLocation`].

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

/// Stable identifier for a node in the Code Property Graph (CPG).
///
/// This is a wrapper around an opaque string so the underlying CPG
/// implementation may switch between string-keyed and integer-keyed
/// schemes without forcing a [`Finding`] schema bump.
///
/// [`Finding`]: crate::Finding
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(pub String);

impl NodeId {
    /// Create a new node id from a borrowed string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

/// Git ref + blame anchor — captures *when* a finding was introduced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GitRef {
    /// 40-char SHA-1 (or 64-char SHA-256) of the commit.
    pub sha: String,
    /// Author email at blame time, if known.
    pub author: Option<String>,
    /// ISO-8601 commit timestamp, if known.
    pub timestamp: Option<String>,
}

/// 1-indexed line/column with absolute byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Position {
    /// 1-indexed line number.
    pub line: u32,
    /// 1-indexed column number (UTF-16 code units, matches LSP).
    pub column: u32,
    /// Absolute byte offset from start of file.
    pub offset: u32,
}

impl Position {
    /// Construct a position. Lines and columns are 1-indexed.
    #[must_use]
    pub const fn new(line: u32, column: u32, offset: u32) -> Self {
        Self {
            line,
            column,
            offset,
        }
    }
}

/// Primary or related source range tied to a Finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// Project-relative path (forward-slash on every OS — guaranteed
    /// by [`camino::Utf8PathBuf`]).
    pub file: Utf8PathBuf,
    /// Inclusive start position.
    pub start: Position,
    /// Exclusive end position.
    pub end: Position,
    /// CPG anchor — preferred over line numbers for fingerprinting.
    pub node_id: Option<NodeId>,
    /// Fully-qualified function/method name, if applicable.
    pub function_qualified_name: Option<String>,
}

/// A secondary location attached to a Finding (e.g. dataflow path step,
/// duplicate-code partner, definition site for a use-site finding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelatedLocation {
    /// The related source range.
    pub location: Location,
    /// Human-readable note describing the relationship.
    pub message: String,
}
