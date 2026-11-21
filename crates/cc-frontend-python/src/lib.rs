//! `cc-frontend-python` — Clean Code V12 Python language frontend.
//!
//! This crate implements [`LanguageFrontend`] for Python: it parses source
//! via `tree-sitter-python` and lifts the resulting concrete syntax tree
//! into a [`cc_cpg::CpgWriteBatch`].
//!
//! # Coverage
//!
//! The lifter understands:
//!
//! - module-level constructs (`module`, `function_definition`, `class_definition`)
//! - control-flow (`if_statement`, `match_statement`, `for_statement`,
//!   `while_statement`, `try_statement`)
//! - expressions (`call`, `identifier`, `string`, `integer`, `float`,
//!   `true`, `false`, `none`, `await`)
//! - statements (`assignment`, `return_statement`, `yield`, `raise_statement`)
//! - declarations (`import_statement`, `import_from_statement`, `decorator`)
//!
//! Constructs the lifter does NOT yet model are surfaced as `Unresolved`
//! marker nodes — see crate-level tests for the canonical follow-up list.
//!
//! # Example
//!
//! ```no_run
//! use cc_cpg::CpgWriteBatch;
//! use cc_frontend::{FileId, LanguageFrontend};
//! use cc_frontend_python::PythonFrontend;
//!
//! let frontend = PythonFrontend::new();
//! let tree = frontend.parse("def f(): pass").expect("parse");
//! let mut batch = CpgWriteBatch::new();
//! let _file_id = frontend
//!     .lift(&tree, "def f(): pass", &mut batch, FileId::new(1))
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
use cc_frontend::{FileId, LanguageFrontend, LiftError, ParseError, TreeSitterTree};

/// Stable language id used by [`PythonFrontend`].
pub const LANGUAGE_ID: &str = "python";

/// File extensions handled by [`PythonFrontend`] (without leading `.`).
pub const FILE_EXTENSIONS: &[&str] = &["py", "pyi"];

/// Python language frontend.
///
/// Cheap to construct; safe to share across threads. Each call to
/// [`Self::parse`] allocates a fresh tree-sitter `Parser`, which is
/// trivial relative to the cost of parsing.
#[derive(Debug, Default, Clone, Copy)]
pub struct PythonFrontend;

impl PythonFrontend {
    /// Construct a new frontend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LanguageFrontend for PythonFrontend {
    fn language_name(&self) -> &'static str {
        LANGUAGE_ID
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        FILE_EXTENSIONS
    }

    fn parse(&self, source: &str) -> Result<TreeSitterTree, ParseError> {
        parser::parse_python(source)
    }

    fn lift(
        &self,
        tree: &TreeSitterTree,
        source: &str,
        store: &mut CpgWriteBatch,
        file_id: FileId,
    ) -> Result<NodeId, LiftError> {
        let root = lift::lift_module(tree, source, store, file_id)?;
        // REFERENCES + CG_CALLS post-passes — run inside `lift` so every
        // caller (kernel runner, integration tests, `FrontendCore`) gets
        // the resolved batch without an extra explicit step.
        self.run_resolution_passes(store);
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_metadata() {
        let f = PythonFrontend::new();
        assert_eq!(f.language_name(), "python");
        assert_eq!(f.file_extensions(), &["py", "pyi"]);
    }
}
