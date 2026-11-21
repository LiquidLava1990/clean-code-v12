//! `cc-frontend-rust` — Clean Code V12 Rust language frontend.
//!
//! Implements [`LanguageFrontend`] for Rust: parses source via
//! `tree-sitter-rust` and lifts the resulting concrete syntax tree into a
//! [`cc_cpg::CpgWriteBatch`].
//!
//! # Coverage
//!
//! The lifter understands:
//!
//! - top-level: `source_file` -> `File` + `Module`
//! - items: `function_item`, `impl_item` (methods), `struct_item`,
//!   `enum_item`, `trait_item`, `union_item`
//! - control-flow: `if_expression`, `match_expression`, `for_expression`,
//!   `while_expression`, `loop_expression`, `try_expression`, `block`
//! - expressions: `call_expression`, `method_call_expression`,
//!   `macro_invocation` (dynamic), `identifier`, literals, `await_expression`
//! - statements: `let_declaration`, `assignment_expression`,
//!   `return_expression`
//! - declarations: `use_declaration`, `extern_crate_declaration`,
//!   `attribute_item`, `line_comment` / `block_comment`
//!
//! Constructs the lifter does NOT yet model are surfaced as `Identifier`
//! markers carrying the original tree-sitter `kind` for follow-up.
//!
//! # Per-language extensions on `Function` / `Method`
//!
//! `lang_ext` carries: `is_unsafe`, `lifetimes`, `where_clauses`,
//! `is_const_fn`, plus the canonical `is_async` mirror (also stored as a
//! top-level `is_async` prop).
//!
//! # Example
//!
//! ```no_run
//! use cc_cpg::CpgWriteBatch;
//! use cc_frontend::{FileId, LanguageFrontend};
//! use cc_frontend_rust::RustFrontend;
//!
//! let frontend = RustFrontend::new();
//! let tree = frontend.parse("fn main() {}").expect("parse");
//! let mut batch = CpgWriteBatch::new();
//! let _file_id = frontend
//!     .lift(&tree, "fn main() {}", &mut batch, FileId::new(1))
//!     .expect("lift");
//! assert!(!batch.nodes().is_empty());
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Module-private helpers prefer `pub(crate)` over plain `pub` for clarity at
// the call site; the workspace `nursery` group flags this as redundant.
#![allow(clippy::redundant_pub_crate)]

mod lift;
mod parser;

use cc_cpg::{CpgWriteBatch, NodeId};
use cc_frontend::call_resolver::{strip_colon_prefix, StripPrefixFn};
use cc_frontend::{FileId, LanguageFrontend, LiftError, ParseError, TreeSitterTree};

/// Stable language id used by [`RustFrontend`].
pub const LANGUAGE_ID: &str = "rust";

/// File extensions handled by [`RustFrontend`] (without leading `.`).
pub const FILE_EXTENSIONS: &[&str] = &["rs"];

/// Rust language frontend.
///
/// Cheap to construct; safe to share across threads. Each call to
/// [`Self::parse`] allocates a fresh tree-sitter `Parser`, which is trivial
/// relative to the cost of parsing.
#[derive(Debug, Default, Clone, Copy)]
pub struct RustFrontend;

impl RustFrontend {
    /// Construct a new frontend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LanguageFrontend for RustFrontend {
    fn language_name(&self) -> &'static str {
        LANGUAGE_ID
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        FILE_EXTENSIONS
    }

    fn parse(&self, source: &str) -> Result<TreeSitterTree, ParseError> {
        parser::parse_rust(source)
    }

    fn lift(
        &self,
        tree: &TreeSitterTree,
        source: &str,
        store: &mut CpgWriteBatch,
        file_id: FileId,
    ) -> Result<NodeId, LiftError> {
        let root = lift::lift_source_file(tree, source, store, file_id)?;
        self.run_resolution_passes(store);
        Ok(root)
    }

    fn callee_strip_prefix(&self) -> StripPrefixFn {
        // Rust callees use `::` as the path separator (`std::time::sleep`,
        // `Self::helper`). Splitting on `.` would mishandle method-call
        // shapes like `recv.method` (where the bare `method` is what we
        // want to match), so we layer both: split on `::` first, then
        // peel any trailing `.method` off the last segment.
        rust_strip_prefix
    }
}

/// Rust-specific callee strip — peel the `::` path prefix, then any
/// trailing `.method` from the last segment so `obj.method` and
/// `crate::module::obj.method` both resolve to bare `method`.
fn rust_strip_prefix(callee: &str) -> &str {
    let last_colon_seg = strip_colon_prefix(callee);
    last_colon_seg.rsplit('.').next().unwrap_or(last_colon_seg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_metadata() {
        let f = RustFrontend::new();
        assert_eq!(f.language_name(), "rust");
        assert_eq!(f.file_extensions(), &["rs"]);
    }
}
