//! `cc-frontend-go` — Clean Code V12 Go language frontend.
//!
//! Mirrors [`cc_frontend_python`] in shape: parses Go source via
//! `tree-sitter-go` and lifts the resulting concrete syntax tree into a
//! [`cc_cpg::CpgWriteBatch`].
//!
//! # Coverage
//!
//! - top-level (`source_file`, `package_clause`, `function_declaration`,
//!   `method_declaration`, `type_declaration` w/ `struct_type` /
//!   `interface_type`)
//! - control flow (`if_statement`, `switch_statement`,
//!   `type_switch_statement`, `select_statement`, `for_statement`)
//! - statements (`defer_statement`, `go_statement`, `return_statement`,
//!   `assignment_statement`, `short_var_declaration`)
//! - expressions (`call_expression`, `identifier`, literals,
//!   `selector_expression`)
//! - declarations (`import_declaration`, `import_spec`, comments)
//!
//! Tree-sitter `ERROR` / `MISSING` nodes are replaced with
//! [`cc_cpg::NodeKind::Identifier`] markers carrying `name = "<error>"` so
//! the AST stays contiguous and downstream queries don't crash on partial
//! parses.
//!
//! # Per-language `Function.lang_ext`
//!
//! Per `docs/design/CPG_SCHEMA.md`, Go functions carry:
//!
//! - `receiver_type: Option<String>` — `Some("*Foo")` for methods,
//!   `None` for free functions
//! - `is_method_value: bool` — true when the callee is a method value
//!   (`x.M` not `x.M()`)
//! - `goroutine_spawned: bool` — true when the enclosing function
//!   contains at least one `go_statement`
//!
//! # Unsupported (out-of-scope for Phase 1)
//!
//! - generic type parameters (Go 1.18+ `[T any]`) — captured as text only
//! - build tags / `//go:build` directives — surface as comments
//! - cgo (`import "C"` is treated as a normal import; `//export` ignored)
//! - channel send/receive operators (`<-`) — not yet a first-class node
//!
//! # Example
//!
//! ```no_run
//! use cc_cpg::CpgWriteBatch;
//! use cc_frontend::{FileId, LanguageFrontend};
//! use cc_frontend_go::GoFrontend;
//!
//! let frontend = GoFrontend::new();
//! let src = "package main\nfunc main() {}\n";
//! let tree = frontend.parse(src).expect("parse");
//! let mut batch = CpgWriteBatch::new();
//! let _ = frontend
//!     .lift(&tree, src, &mut batch, FileId::new(1))
//!     .expect("lift");
//! assert!(!batch.nodes().is_empty());
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::redundant_pub_crate)]

mod lift;
mod parser;

use cc_cpg::{CpgWriteBatch, NodeId};
use cc_frontend::{FileId, LanguageFrontend, LiftError, ParseError, TreeSitterTree};

/// Stable language id used by [`GoFrontend`].
pub const LANGUAGE_ID: &str = "go";

/// File extensions handled by [`GoFrontend`] (without leading `.`).
pub const FILE_EXTENSIONS: &[&str] = &["go"];

/// Go language frontend.
///
/// Cheap to construct; safe to share across threads. Each call to
/// [`Self::parse`] allocates a fresh tree-sitter `Parser`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GoFrontend;

impl GoFrontend {
    /// Construct a new frontend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LanguageFrontend for GoFrontend {
    fn language_name(&self) -> &'static str {
        LANGUAGE_ID
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        FILE_EXTENSIONS
    }

    fn parse(&self, source: &str) -> Result<TreeSitterTree, ParseError> {
        parser::parse_go(source)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_metadata() {
        let f = GoFrontend::new();
        assert_eq!(f.language_name(), "go");
        assert_eq!(f.file_extensions(), &["go"]);
    }
}
