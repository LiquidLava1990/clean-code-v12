//! `cc-incremental` — Salsa-based incremental query layer for Clean Code V12.
//!
//! Sits between the language frontends ([`cc_frontend`]), the in-memory CPG
//! ([`cc_cpg`]), the persistent store ([`cc_cpg_store`]), and the rule engine
//! ([`cc_rules`]). The job of this crate is one thing: **make file-change ->
//! recompute paths cheap**. When a single file changes in a 100k-LOC repo
//! only the queries depending on that file's content rerun; everything else
//! (other files' findings, repo-wide score) is served from the salsa cache.
//!
//! # Design — inputs + tracked free functions
//!
//! Salsa 0.18 supports both `#[salsa::tracked] struct` and
//! `#[salsa::tracked] fn` patterns. We deliberately use the **inputs +
//! tracked-free-functions** pattern (see W1.T6 spec note in
//! the Phase-1 design) because:
//!
//! 1. The query inputs (parsed tree, CPG batch, finding list) come from
//!    foreign types we cannot derive [`salsa::Update`] on — wrapping them in
//!    local newtypes that carry a manual [`Update`] impl is straightforward
//!    only when they appear as **return values** of tracked functions, not
//!    as fields of tracked structs (where salsa needs structural equality).
//! 2. The cache-invalidation signal is a single `content_hash` field on
//!    [`FileInput`]; setter-driven inputs map cleanly onto that.
//!
//! # Modules
//!
//! - [`db`] — the [`db::CcDatabase`] struct + salsa storage wiring.
//! - [`inputs`] — [`inputs::FileInput`], [`inputs::RepoInput`],
//!   [`inputs::RuleInput`].
//! - [`queries`] — `parsed_tree`, `cpg_root`, `findings_for`,
//!   `health_score_for_file`, `repo_health_score`.
//! - [`watcher`] — `notify`-based file watcher that hashes on change and
//!   calls back into the database.
//! - [`error`] — [`error::IncrementalError`] surface.
//!
//! # Example
//!
//! ```no_run
//! use cc_incremental::{CcDatabase, ContentHash};
//!
//! let mut db = CcDatabase::new();
//! let file = db.add_file("src/lib.rs", "fn main() {}", "rust");
//! let _findings = db.findings_for(file);
//! // Same content -> cache hit, no recompute.
//! let changed = db.update_file(file, "fn main() {}");
//! assert!(!changed);
//! ```

// NOTE: `unsafe_code` is `deny` (not `forbid`) crate-wide — overridden
// from the workspace `forbid` in this crate's Cargo.toml. The salsa
// `Update` trait is `unsafe` by design (see `queries::wrappers` and
// `inputs::ContentHash`'s manual impls). All `unsafe` is documented +
// locally `# Safety`'d.
// `missing_docs` is `warn` (workspace-aligned) rather than `deny`
// because the salsa input/tracked macros expand to a host of generated
// associated items (`new`, `path`, `set_path`, ...) that we cannot
// individually document without forking the macros. Public surface
// items written by hand in this crate ARE all documented.
#![warn(missing_docs)]

#[macro_use]
mod update_macros;

pub mod db;
pub mod error;
pub mod inputs;
pub mod queries;
pub mod watcher;

pub use db::CcDatabase;
pub use error::{IncrementalError, IncrementalResult};
pub use inputs::{ContentHash, FileInput, RepoInput, RuleInput};
pub use queries::{CachedCpg, CachedFindings, CachedTree};
pub use watcher::{WatcherEvent, WatcherHandle};
