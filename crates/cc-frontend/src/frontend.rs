//! The core [`LanguageFrontend`] trait + [`FileId`] newtype.
//!
//! This module is intentionally tiny — keeping the trait isolated from the
//! registry / orchestration layer means the four sibling crates
//! (`cc-frontend-python`, `cc-frontend-typescript`, `cc-frontend-go`,
//! `cc-frontend-rust`) only need to depend on this surface to implement a
//! frontend.

use cc_cpg::{CpgWriteBatch, NodeId};
use serde::{Deserialize, Serialize};

use crate::call_resolver::{self, StripPrefixFn};
use crate::default_resolver;
use crate::errors::{LiftError, ParseError, ResolveError};
use crate::tree::TreeSitterTree;

/// Stable, repo-scoped file identifier.
///
/// Frontends do not allocate `FileId`s — the kernel does (typically
/// `FileId(repo_path_hash)` or a monotonic counter). Frontends just
/// thread it through the lift call so every node can reference its
/// originating file via the `by_file` index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[repr(transparent)]
pub struct FileId(pub u64);

impl FileId {
    /// Construct a `FileId` from a raw `u64` — kept explicit so the call
    /// site reads as a deliberate id allocation.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw underlying value. Use sparingly; prefer the newtype.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A per-language frontend.
///
/// Implementors:
/// - `cc-frontend-python` — tree-sitter-python
/// - `cc-frontend-typescript` — tree-sitter-typescript
/// - `cc-frontend-go` — tree-sitter-go
/// - `cc-frontend-rust` — tree-sitter-rust
///
/// Frontends are thread-safe (`Send + Sync`); the kernel may parse-and-lift
/// many files in parallel from a single registered instance.
pub trait LanguageFrontend: Send + Sync {
    /// Stable language name (e.g. `"python"`, `"typescript"`).
    fn language_name(&self) -> &'static str;

    /// File extensions, **without** leading `.` (e.g. `["py", "pyi"]`).
    fn file_extensions(&self) -> &'static [&'static str];

    /// Parse `source` into a tree-sitter tree.
    ///
    /// # Errors
    ///
    /// See [`ParseError`] — returns when the grammar is missing, the source
    /// can't be encoded, or tree-sitter signals an unrecoverable parse.
    fn parse(&self, source: &str) -> Result<TreeSitterTree, ParseError>;

    /// Lift a parsed tree into the CPG, returning the root [`NodeId`].
    ///
    /// Lift errors are non-fatal **by convention**: the frontend SHOULD
    /// insert an `Unresolved` marker and continue. A returned [`LiftError`]
    /// should only happen for catastrophic failures the frontend can't
    /// recover from (out-of-memory, panic-equivalent).
    ///
    /// # Errors
    ///
    /// Returns [`LiftError`] only on unrecoverable failure.
    fn lift(
        &self,
        tree: &TreeSitterTree,
        source: &str,
        store: &mut CpgWriteBatch,
        file_id: FileId,
    ) -> Result<NodeId, LiftError>;

    /// Resolve identifier names to declarations, emitting `REFERENCES`
    /// edges. The default impl walks `AST_PARENT` chains for lexical
    /// scoping; frontends with non-lexical rules (Python `global`, JS
    /// hoisting, Go package visibility) override this.
    ///
    /// # Errors
    ///
    /// Returns the first unresolved-identifier diagnostic the resolver
    /// produces. Most callers treat this as a soft warning.
    fn resolve_names(&self, store: &mut CpgWriteBatch) -> Result<(), ResolveError> {
        default_resolver::resolve(store)
    }

    /// Resolve every `Call` node to its in-batch callee `Function` /
    /// `Method`, emitting `CG_CALLS` edges. The default impl uses
    /// [`call_resolver::strip_dot_prefix`]; Rust overrides with
    /// [`call_resolver::strip_colon_prefix`].
    ///
    /// Frontends needing whole-program / cross-file resolution override
    /// this and call into the persistent store; the default-impl is a
    /// strict per-batch lexical resolver.
    ///
    /// # Errors
    ///
    /// Returns the first call-resolution failure the resolver produces.
    /// In practice this never triggers — every endpoint is always within
    /// the batch we just walked — but the signature stays `Result` so
    /// the cross-file impl can fail loudly.
    fn resolve_calls(&self, store: &mut CpgWriteBatch) -> Result<(), ResolveError> {
        call_resolver::resolve(store, self.callee_strip_prefix())
    }

    /// Function used by [`Self::resolve_calls`] to strip language-specific
    /// callee prefixes (`obj.method` -> `method`, `std::sleep` -> `sleep`).
    /// Frontends override this rather than reimplementing
    /// [`Self::resolve_calls`] when only the strip rule differs.
    fn callee_strip_prefix(&self) -> StripPrefixFn {
        call_resolver::strip_dot_prefix
    }

    /// Run the standard post-lift resolution passes — `resolve_names`
    /// (`REFERENCES` edges) followed by `resolve_calls` (`CG_CALLS` edges).
    ///
    /// Failures from either pass are logged via `tracing::warn!` and
    /// swallowed: the lifted batch is still useful to AST-only rules,
    /// and rule packs that need resolution gracefully degrade when a
    /// batch carries no `REFERENCES` / `CG_CALLS` edges.
    ///
    /// Frontends call this from inside their `lift` implementation so
    /// every caller (kernel runner, integration tests, `FrontendCore`)
    /// gets the resolved batch transparently.
    fn run_resolution_passes(&self, store: &mut CpgWriteBatch) {
        if let Err(err) = self.resolve_names(store) {
            tracing::warn!(
                target: "cc_frontend::resolution",
                language = self.language_name(),
                error = %err,
                "name resolver returned a diagnostic; continuing"
            );
        }
        if let Err(err) = self.resolve_calls(store) {
            tracing::warn!(
                target: "cc_frontend::resolution",
                language = self.language_name(),
                error = %err,
                "call resolver returned a diagnostic; continuing"
            );
        }
    }
}
