//! Graph nodes — 24 [`NodeKind`] variants, each carrying a typed property
//! bag.
//!
//! Properties are intentionally schema-light: required props per kind are
//! documented in `docs/design/CPG_SCHEMA.md` and validated by frontends, not by
//! the type system. This keeps the type small (one `Node` for all kinds) and
//! lets partial CPGs survive lift errors.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::value::Value;

/// Stable identifier for a node within a [`crate::CpgWriteBatch`] or store.
///
/// Newtype around `u64` — no `From<u64>` is provided so callers can never
/// fabricate ids out of thin air. Use [`NodeId::new`] when reconstructing
/// from on-disk encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(u64);

impl NodeId {
    /// Construct an id from a raw `u64`.
    ///
    /// Reserved for store / serde round-trip; frontends should let
    /// [`crate::CpgWriteBatch::push_node`] allocate ids instead.
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

/// One of the 24 syntactic / semantic node kinds.
///
/// Adding or removing a variant is a breaking schema change — bump
/// [`crate::SCHEMA_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    /// Source file root.
    File,
    /// Module / package / namespace.
    Module,
    /// Class / struct / interface / trait.
    Class,
    /// Free function or top-level function.
    Function,
    /// Method on a class (subtype of [`NodeKind::Function`]).
    Method,
    /// Function parameter.
    Parameter,
    /// Local, module, or class variable.
    Variable,
    /// Compound statement / brace block.
    Block,
    /// Conditional branch — `if` / `switch` / `match` / ternary.
    Branch,
    /// Loop — `for` / `while` / `do-while` / range.
    Loop,
    /// Try / catch / finally / except construct.
    Try,
    /// Function or method invocation.
    Call,
    /// Variable / field / global read access.
    Read,
    /// Variable / field / global write (assignment).
    Write,
    /// Constant literal — string / int / float / bool / null.
    Literal,
    /// Bare name reference (pre-resolution).
    Identifier,
    /// Type annotation or inferred type.
    Type,
    /// `await` / `async with` / `async for` wrapper.
    Async,
    /// Domain event emit (framework-aware).
    Event,
    /// Call or import that crosses the repo boundary (stdlib / dep / native).
    External,
    /// Comment block.
    Comment,
    /// Python decorator / TypeScript decorator / Rust attribute.
    Decorator,
    /// Import / use / require statement.
    Import,
    /// Return / yield / throw.
    Return,
}

impl NodeKind {
    /// All 24 variants in declaration order. Useful for exhaustive tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::File,
            Self::Module,
            Self::Class,
            Self::Function,
            Self::Method,
            Self::Parameter,
            Self::Variable,
            Self::Block,
            Self::Branch,
            Self::Loop,
            Self::Try,
            Self::Call,
            Self::Read,
            Self::Write,
            Self::Literal,
            Self::Identifier,
            Self::Type,
            Self::Async,
            Self::Event,
            Self::External,
            Self::Comment,
            Self::Decorator,
            Self::Import,
            Self::Return,
        ]
    }
}

/// A graph node — kind + property bag.
///
/// `Node` is a single concrete type (rather than an enum-of-structs) so that
/// storage and indexing are uniform across kinds. Per-kind required props are
/// validated by frontends against the schema doc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    /// Stable id within the owning batch / store.
    pub id: NodeId,
    /// Discriminant.
    pub kind: NodeKind,
    /// Typed property bag. Keys are stable string names from the schema doc.
    pub props: BTreeMap<String, Value>,
}

impl Node {
    /// Construct a node directly. Prefer [`crate::NodeBuilder`] in frontends.
    #[must_use]
    pub const fn new(id: NodeId, kind: NodeKind, props: BTreeMap<String, Value>) -> Self {
        Self { id, kind, props }
    }

    /// Borrow a named property if present.
    #[must_use]
    pub fn prop(&self, key: &str) -> Option<&Value> {
        self.props.get(key)
    }
}
