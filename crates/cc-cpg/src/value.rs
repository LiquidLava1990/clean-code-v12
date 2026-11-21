//! Typed property values backing every node and edge property bag.
//!
//! `Value` is intentionally small: 13 variants covering primitives, byte
//! strings, node references, source positions, hashes, and a `Map` for
//! frontend `lang_ext` extension blobs. No free-form strings escape from a
//! frontend without going through this enum.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::hash::Sha256;
use crate::node::NodeId;
use crate::position::{Position, Range};

/// Typed property value stored in a node or edge property bag.
///
/// Variants are ordered roughly by frequency at lift-time: primitives first,
/// node references next, then structured values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// Absence of a value (distinct from "key missing from bag").
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed 64-bit integer.
    Int(i64),
    /// Unsigned 64-bit integer.
    Uint(u64),
    /// 64-bit float (IEEE-754; `NaN != NaN` per `PartialEq`).
    Float(f64),
    /// UTF-8 string.
    String(String),
    /// Raw bytes (literal byte strings, embedded blobs).
    Bytes(Vec<u8>),
    /// Reference to another node in the same batch / store.
    NodeRef(NodeId),
    /// Ordered list of node references.
    NodeList(Vec<NodeId>),
    /// Single source position.
    Position(Position),
    /// Source range.
    Range(Range),
    /// Content hash.
    Hash(Sha256),
    /// Nested string-keyed map. Reserved for `lang_ext` and similar
    /// frontend-owned extension blobs.
    Map(BTreeMap<String, Value>),
}

impl Value {
    /// Short tag name useful for diagnostics + tracing.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Uint(_) => "uint",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::Bytes(_) => "bytes",
            Self::NodeRef(_) => "node_ref",
            Self::NodeList(_) => "node_list",
            Self::Position(_) => "position",
            Self::Range(_) => "range",
            Self::Hash(_) => "hash",
            Self::Map(_) => "map",
        }
    }

    /// Borrow as a string slice if this is a `String` variant.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Borrow as `i64` if this is an `Int` variant.
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Borrow as `bool` if this is a `Bool` variant.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}
impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Self::Uint(v)
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}
impl From<NodeId> for Value {
    fn from(v: NodeId) -> Self {
        Self::NodeRef(v)
    }
}
impl From<Vec<NodeId>> for Value {
    fn from(v: Vec<NodeId>) -> Self {
        Self::NodeList(v)
    }
}
impl From<Position> for Value {
    fn from(v: Position) -> Self {
        Self::Position(v)
    }
}
impl From<Range> for Value {
    fn from(v: Range) -> Self {
        Self::Range(v)
    }
}
impl From<Sha256> for Value {
    fn from(v: Sha256) -> Self {
        Self::Hash(v)
    }
}
