//! `cc-cpg` — Clean Code V12 Code Property Graph schema.
//!
//! Pure-data crate: types, builders, validation, serde. **No I/O, no graph
//! store** — that lives in `cc-cpg-store`.
//!
//! # Schema overview
//!
//! - 24 [`NodeKind`] variants, each carrying a typed property bag.
//! - 12 [`EdgeKind`] variants — typed, directional graph relationships.
//! - Property values typed via the [`Value`] enum.
//! - [`NodeId`] / [`EdgeId`] newtypes — never raw `u64`.
//! - [`SCHEMA_VERSION`] constant — bumping it invalidates all caches.
//!
//! # Frontend lift contract
//!
//! Language frontends populate a [`CpgWriteBatch`] using [`NodeBuilder`] and
//! [`EdgeBuilder`]. The batch is immutable once finalized and is consumed by
//! `cc-cpg-store` for persistence.
//!
//! See `docs/design/CPG_SCHEMA.md` at the repo root for the design doctrine.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod builder;
mod edge;
mod error;
mod hash;
mod node;
mod position;
mod value;

pub use builder::{CpgWriteBatch, EdgeBuilder, NodeBuilder};
pub use edge::{Edge, EdgeId, EdgeKind};
pub use error::{CpgError, CpgResult};
pub use hash::Sha256;
pub use node::{Node, NodeId, NodeKind};
pub use position::{Position, Range};
pub use value::Value;

/// Current CPG schema version.
///
/// Bump on any [`NodeKind`] / [`EdgeKind`] variant addition or property-shape
/// change. `cc-cpg-store` reads this on open and rejects mismatched stores.
pub const SCHEMA_VERSION: u32 = 1;
