//! `cc-cpg-store` — redb-backed persistent store for the Clean Code V12
//! Code Property Graph.
//!
//! This crate consumes finished [`cc_cpg::CpgWriteBatch`] instances produced
//! by language frontends and persists them into a versioned on-disk store.
//! It exposes indexed read queries used by the rule engine
//! (`cc-rules-tier0`), the LSP (`cc-lsp`), and the CLI (`cc-cli`).
//!
//! # Architecture
//!
//! ```text
//! frontend ──► CpgWriteBatch ──► CpgStore::write_batch ──► redb file
//!                                          │
//!                                          ▼
//!                              indexed read queries
//! ```
//!
//! # Tables
//!
//! Eight redb tables (see `docs/design/CPG_SCHEMA.md`):
//!
//! - `nodes`       — `NodeId → bincode(Node)`
//! - `edges`       — `EdgeId → bincode(Edge)`
//! - `by_kind`     — `(NodeKind, NodeId) → ()`
//! - `by_file`     — `(FileId, NodeId) → ()`
//! - `edges_out`   — `(NodeId, EdgeKind, NodeId) → EdgeId`
//! - `edges_in`    — `(NodeId, EdgeKind, NodeId) → EdgeId`
//! - `meta`        — `&str → bincode(value)` (schema version, path↦FileId)
//! - `strings`     — `u64 → &str` (intern pool, hook for Phase 1.5)
//!
//! # Concurrency
//!
//! [`CpgStore`] is `Send + Sync` and cheaply cloneable. redb provides MVCC,
//! so any number of readers can run concurrently with at most one writer.
//!
//! # Schema versioning
//!
//! [`CpgStore::open`] performs a schema-version handshake against
//! [`cc_cpg::SCHEMA_VERSION`]. Mismatched stores are rejected with an
//! actionable error; callers should rebuild caches when this happens.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Intentional crate-style choices:
// - `pub(crate)` is used in private modules to make the per-module surface
//   explicit (private modules are an organisational concept here, not a
//   visibility one); flipping to `pub` would over-expose the items.
// - `doc_markdown` flags every CamelCase or SCREAMING_SNAKE name in narrative
//   docstrings; the references to `NodeId`, `EdgeId`, `AST_PARENT`, etc. are
//   intentionally bare in prose.
#![allow(clippy::redundant_pub_crate, clippy::doc_markdown)]

mod codec;
mod error;
mod meta;
mod read;
mod store;
mod tables;
mod write;

pub use cc_frontend::FileId;
pub use error::{StoreError, StoreResult};
pub use read::{EdgeIter, NodeIdIter, NodeIter};
pub use store::CpgStore;
pub use write::WriteSummary;
