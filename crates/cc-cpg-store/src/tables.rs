//! redb table definitions.
//!
//! All table names are stable on-disk identifiers — renaming any of them is a
//! schema-breaking change and requires bumping
//! [`cc_cpg::SCHEMA_VERSION`].
//!
//! Composite keys are encoded as fixed-width tuples so that prefix scans work:
//! `(NodeKind as u8, NodeId as u64)` lets us iterate every node of one kind
//! with a single bounded range scan.

use cc_cpg::NodeKind;
use redb::TableDefinition;

/// `nodes`: `NodeId (u64)` → bincode(Node).
pub(crate) const NODES: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("nodes");

/// `edges`: `EdgeId (u64)` → bincode(Edge).
pub(crate) const EDGES: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("edges");

/// `by_kind`: `(NodeKind as u8, NodeId as u64)` → `()` — kind-scoped index.
pub(crate) const BY_KIND: TableDefinition<'static, (u8, u64), ()> = TableDefinition::new("by_kind");

/// `by_file`: `(FileId as u64, NodeId as u64)` → `()` — file-scoped
/// invalidation index. Populated when a node carries a `file_id` property
/// or when the caller of `write_batch` supplies an explicit `FileId`.
pub(crate) const BY_FILE: TableDefinition<'static, (u64, u64), ()> =
    TableDefinition::new("by_file");

/// `edges_out`: `(NodeId, EdgeKind as u8, NodeId)` → `EdgeId (u64)`.
pub(crate) const EDGES_OUT: TableDefinition<'static, (u64, u8, u64), u64> =
    TableDefinition::new("edges_out");

/// `edges_in`: `(NodeId target, EdgeKind as u8, NodeId source)` → `EdgeId`.
///
/// Note the key ordering: target is the prefix so reverse-traversal is a
/// bounded prefix scan.
pub(crate) const EDGES_IN: TableDefinition<'static, (u64, u8, u64), u64> =
    TableDefinition::new("edges_in");

/// `meta`: `&str` → bincode(`serde_json::Value`-ish payload).
///
/// Used for `schema_version`, `repo_path`, and the `path → FileId` map.
pub(crate) const META: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("meta");

/// `strings`: `StringId (u64)` → `&str`.
///
/// Hook for Phase 1.5 string interning. Currently unused at write time so the
/// table stays empty, but the definition ships now so opening an old store
/// after Phase 1.5 doesn't trigger a schema-version bump.
#[allow(dead_code)] // reserved for Phase 1.5 dedup work
pub(crate) const STRINGS: TableDefinition<'static, u64, &'static str> =
    TableDefinition::new("strings");

/// All tables that must exist after `open()` completes. Used by the
/// initialization pass to materialise empty tables on first open.
#[allow(dead_code)] // reserved for Phase 4 maintenance commands
pub(crate) const ALL_TABLE_NAMES: &[&str] = &[
    "nodes",
    "edges",
    "by_kind",
    "by_file",
    "edges_out",
    "edges_in",
    "meta",
    "strings",
];

/// Stable u8 discriminant for a [`NodeKind`].
///
/// We keep this mapping centralised so renaming a variant doesn't silently
/// change its on-disk byte. Any change to this function is a schema break.
pub(crate) const fn node_kind_tag(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::File => 0,
        NodeKind::Module => 1,
        NodeKind::Class => 2,
        NodeKind::Function => 3,
        NodeKind::Method => 4,
        NodeKind::Parameter => 5,
        NodeKind::Variable => 6,
        NodeKind::Block => 7,
        NodeKind::Branch => 8,
        NodeKind::Loop => 9,
        NodeKind::Try => 10,
        NodeKind::Call => 11,
        NodeKind::Read => 12,
        NodeKind::Write => 13,
        NodeKind::Literal => 14,
        NodeKind::Identifier => 15,
        NodeKind::Type => 16,
        NodeKind::Async => 17,
        NodeKind::Event => 18,
        NodeKind::External => 19,
        NodeKind::Comment => 20,
        NodeKind::Decorator => 21,
        NodeKind::Import => 22,
        NodeKind::Return => 23,
    }
}

/// Stable u8 discriminant for an [`EdgeKind`].
pub(crate) const fn edge_kind_tag(kind: cc_cpg::EdgeKind) -> u8 {
    use cc_cpg::EdgeKind as E;
    match kind {
        E::AST_PARENT => 0,
        E::CFG_NEXT => 1,
        E::CFG_BRANCH_TRUE => 2,
        E::CFG_BRANCH_FALSE => 3,
        E::PDG_DATA => 4,
        E::PDG_CONTROL => 5,
        E::CG_CALLS => 6,
        E::CG_OVERRIDES => 7,
        E::DECLARES => 8,
        E::REFERENCES => 9,
        E::EVALUATES_TO => 10,
        E::RAISES => 11,
    }
}
