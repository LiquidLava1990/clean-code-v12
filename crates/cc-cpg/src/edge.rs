//! Graph edges — 12 typed [`EdgeKind`] variants.
//!
//! Edges are directional: `from → to`. The on-disk store maintains both an
//! `edges_out` and `edges_in` index for O(1) traversal in either direction.
//! See `docs/design/CPG_SCHEMA.md` for the per-edge endpoint contract.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::node::NodeId;
use crate::value::Value;

/// Stable identifier for an edge within a batch or store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EdgeId(u64);

impl EdgeId {
    /// Construct an id from a raw `u64` (storage / serde round-trip only).
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the wrapped `u64` for storage encoding.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One of the 12 typed edge kinds.
///
/// Naming matches Joern conventions where they overlap, with three
/// CC-V12-specific additions: `EVALUATES_TO` for inferred type, `RAISES` for
/// effect annotations, and `DECLARES` for module-scope name binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum EdgeKind {
    /// Lexical containment: child → parent.
    AST_PARENT,
    /// Control-flow successor: stmt → stmt.
    CFG_NEXT,
    /// True-arm successor: `Branch` → stmt.
    CFG_BRANCH_TRUE,
    /// False/else-arm successor: `Branch` → stmt.
    CFG_BRANCH_FALSE,
    /// Data dependence: definition → use.
    PDG_DATA,
    /// Control dependence: predicate → controlled stmt.
    PDG_CONTROL,
    /// Resolved call: `Call` → `Function`.
    CG_CALLS,
    /// Method override: subclass method → superclass method.
    CG_OVERRIDES,
    /// Top-level declaration: `Module` → symbol.
    DECLARES,
    /// Name resolution: `Identifier` → declaration.
    REFERENCES,
    /// Inferred type: expression → `Type`.
    EVALUATES_TO,
    /// Effects annotation: `Function` → exception type.
    RAISES,
}

impl EdgeKind {
    /// All 12 variants in declaration order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::AST_PARENT,
            Self::CFG_NEXT,
            Self::CFG_BRANCH_TRUE,
            Self::CFG_BRANCH_FALSE,
            Self::PDG_DATA,
            Self::PDG_CONTROL,
            Self::CG_CALLS,
            Self::CG_OVERRIDES,
            Self::DECLARES,
            Self::REFERENCES,
            Self::EVALUATES_TO,
            Self::RAISES,
        ]
    }
}

/// A directional graph edge.
///
/// `props` is reserved for edge-level metadata (e.g. `confidence` on a
/// resolved call edge). Most edges leave it empty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    /// Stable id within the owning batch / store.
    pub id: EdgeId,
    /// Edge variant.
    pub kind: EdgeKind,
    /// Source endpoint.
    pub from: NodeId,
    /// Target endpoint.
    pub to: NodeId,
    /// Optional typed metadata.
    pub props: BTreeMap<String, Value>,
}

impl Edge {
    /// Construct an edge directly. Prefer [`crate::EdgeBuilder`] in frontends.
    #[must_use]
    pub const fn new(id: EdgeId, kind: EdgeKind, from: NodeId, to: NodeId) -> Self {
        Self {
            id,
            kind,
            from,
            to,
            props: BTreeMap::new(),
        }
    }
}
