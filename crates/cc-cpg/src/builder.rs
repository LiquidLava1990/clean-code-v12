//! Frontend-facing builders.
//!
//! Frontends lift tree-sitter trees into a [`CpgWriteBatch`] using
//! [`NodeBuilder`] and [`EdgeBuilder`]. The batch allocates ids, validates
//! references, and is consumed (in full) by `cc-cpg-store::write_batch`.
//!
//! # Example
//!
//! ```
//! use cc_cpg::{CpgWriteBatch, EdgeKind, NodeBuilder, NodeKind, Value};
//!
//! let mut batch = CpgWriteBatch::new();
//! let file = batch.push_node(
//!     NodeBuilder::new(NodeKind::File)
//!         .with_prop("path", Value::String("src/lib.rs".into()))
//!         .with_prop("language", Value::String("rust".into())),
//! );
//! let module = batch.push_node(
//!     NodeBuilder::new(NodeKind::Module).with_prop("name", Value::String("lib".into())),
//! );
//! batch.push_edge(EdgeKind::AST_PARENT, module, file).unwrap();
//! assert_eq!(batch.nodes().len(), 2);
//! assert_eq!(batch.edges().len(), 1);
//! ```

use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

use crate::edge::{Edge, EdgeId, EdgeKind};
use crate::error::{CpgError, CpgResult};
use crate::node::{Node, NodeId, NodeKind};
use crate::value::Value;

/// Builds a single [`Node`] before insertion into a [`CpgWriteBatch`].
///
/// Builders are cheap value objects: construct, configure, hand to the batch.
#[derive(Debug, Clone)]
pub struct NodeBuilder {
    kind: NodeKind,
    props: BTreeMap<String, Value>,
}

impl NodeBuilder {
    /// Start a new builder for the given kind.
    #[must_use]
    pub const fn new(kind: NodeKind) -> Self {
        Self {
            kind,
            props: BTreeMap::new(),
        }
    }

    /// Replace the kind. Useful when up-classifying `Function` → `Method`
    /// after the receiver class is known.
    #[must_use]
    pub const fn with_kind(mut self, kind: NodeKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set a property. Existing keys are overwritten.
    #[must_use]
    pub fn with_prop(mut self, key: impl Into<String>, value: Value) -> Self {
        self.props.insert(key.into(), value);
        self
    }

    /// Convenience: set the canonical `path` property from a UTF-8 path.
    #[must_use]
    pub fn with_path(self, path: Utf8PathBuf) -> Self {
        self.with_prop("path", Value::String(path.into_string()))
    }

    /// Materialize into a [`Node`] with the given id.
    ///
    /// Reserved for the batch — frontends should call
    /// [`CpgWriteBatch::push_node`] rather than building nodes directly.
    fn finish(self, id: NodeId) -> Node {
        Node::new(id, self.kind, self.props)
    }
}

/// Builds a single [`Edge`] before insertion into a [`CpgWriteBatch`].
#[derive(Debug, Clone)]
pub struct EdgeBuilder {
    kind: EdgeKind,
    from: NodeId,
    to: NodeId,
    props: BTreeMap<String, Value>,
}

impl EdgeBuilder {
    /// Start a new edge builder.
    #[must_use]
    pub const fn new(kind: EdgeKind, from: NodeId, to: NodeId) -> Self {
        Self {
            kind,
            from,
            to,
            props: BTreeMap::new(),
        }
    }

    /// Set an edge-level property.
    #[must_use]
    pub fn with_prop(mut self, key: impl Into<String>, value: Value) -> Self {
        self.props.insert(key.into(), value);
        self
    }

    fn finish(self, id: EdgeId) -> Edge {
        Edge {
            id,
            kind: self.kind,
            from: self.from,
            to: self.to,
            props: self.props,
        }
    }
}

/// A buffered sequence of nodes + edges destined for the store.
///
/// Frontends populate this; `cc-cpg-store::write_batch` consumes it. Ids are
/// allocated densely starting at 1 — `0` is reserved as a sentinel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpgWriteBatch {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    next_node_id: u64,
    next_edge_id: u64,
}

impl CpgWriteBatch {
    /// Construct an empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            next_node_id: 1,
            next_edge_id: 1,
        }
    }

    /// Push a node, allocate its id, and return that id.
    pub fn push_node(&mut self, builder: NodeBuilder) -> NodeId {
        let id = NodeId::new(self.next_node_id);
        self.next_node_id += 1;
        self.nodes.push(builder.finish(id));
        id
    }

    /// Push an edge between two already-pushed nodes.
    ///
    /// # Errors
    ///
    /// Returns [`CpgError::DanglingEdge`] if either endpoint id has not been
    /// produced by this batch.
    pub fn push_edge(&mut self, kind: EdgeKind, from: NodeId, to: NodeId) -> CpgResult<EdgeId> {
        self.push_edge_with(EdgeBuilder::new(kind, from, to))
    }

    /// Push a fully-built edge.
    ///
    /// # Errors
    ///
    /// Returns [`CpgError::DanglingEdge`] if either endpoint id is not in this
    /// batch's allocated range.
    pub fn push_edge_with(&mut self, builder: EdgeBuilder) -> CpgResult<EdgeId> {
        self.ensure_known(builder.kind, builder.from)?;
        self.ensure_known(builder.kind, builder.to)?;
        let id = EdgeId::new(self.next_edge_id);
        self.next_edge_id += 1;
        self.edges.push(builder.finish(id));
        Ok(id)
    }

    /// Borrow the accumulated nodes.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Borrow the accumulated edges.
    #[must_use]
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Consume the batch into its component vectors.
    #[must_use]
    pub fn into_parts(self) -> (Vec<Node>, Vec<Edge>) {
        (self.nodes, self.edges)
    }

    const fn ensure_known(&self, kind: EdgeKind, id: NodeId) -> CpgResult<()> {
        if id.get() == 0 || id.get() >= self.next_node_id {
            return Err(CpgError::DanglingEdge { kind, id });
        }
        Ok(())
    }
}
