//! `cc-frontend-typescript` — Clean Code V12 TypeScript / TSX / JavaScript
//! language frontend.
//!
//! This crate implements [`LanguageFrontend`] for the TypeScript family: it
//! parses source via `tree-sitter-typescript` (selecting `LANGUAGE_TYPESCRIPT`
//! for `.ts` / `.mts` / `.cts` / `.js` / `.mjs` / `.cjs` and `LANGUAGE_TSX`
//! for `.tsx` / `.jsx`) and lifts the resulting concrete syntax tree into a
//! [`cc_cpg::CpgWriteBatch`].
//!
//! # Coverage
//!
//! The lifter understands:
//!
//! - module-level constructs (`program`, `function_declaration`,
//!   `class_declaration`, `interface_declaration`)
//! - members (`method_definition`, `arrow_function`, `public_field_definition`)
//! - control-flow (`if_statement`, `switch_statement`, `ternary_expression`,
//!   `for_statement`, `while_statement`, `do_statement`, `for_in_statement`,
//!   `for_of_statement`, `try_statement` / `catch_clause`)
//! - expressions (`call_expression`, `identifier`, `string`, `number`,
//!   `template_string`, `regex`, `true` / `false` / `null` / `undefined`,
//!   `await_expression`, `assignment_expression`, `augmented_assignment_expression`)
//! - declarations (`import_statement` / `import_clause`, `decorator`)
//! - returns (`return_statement`, `throw_statement`, `yield_expression`)
//!
//! Constructs the lifter does NOT yet model are surfaced as `Unresolved`
//! marker nodes — TS-specific examples include `enum_declaration`,
//! `type_alias_declaration`, `internal_module` (namespace),
//! `satisfies_expression`, `conditional_type`, `mapped_type`,
//! `template_literal_type`, and decorator-with-arguments shapes.
//!
//! # Example
//!
//! ```no_run
//! use cc_cpg::CpgWriteBatch;
//! use cc_frontend::{FileId, LanguageFrontend};
//! use cc_frontend_typescript::TypescriptFrontend;
//!
//! let frontend = TypescriptFrontend::new();
//! let tree = frontend.parse("function f() {}").expect("parse");
//! let mut batch = CpgWriteBatch::new();
//! let _file_id = frontend
//!     .lift(&tree, "function f() {}", &mut batch, FileId::new(1))
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

pub use parser::is_tsx_extension;

use cc_cpg::{CpgWriteBatch, NodeId};
use cc_frontend::{FileId, LanguageFrontend, LiftError, ParseError, TreeSitterTree};

/// Stable language id used by [`TypescriptFrontend`].
pub const LANGUAGE_ID: &str = "typescript";

/// File extensions handled by [`TypescriptFrontend`] (without leading `.`).
///
/// Order matters for documentation only — extension lookup is unordered.
/// `tsx` and `jsx` route to `LANGUAGE_TSX`; the rest route to
/// `LANGUAGE_TYPESCRIPT`. See [`parser::is_tsx_extension`].
pub const FILE_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];

/// TypeScript / TSX / JavaScript frontend.
///
/// Cheap to construct; safe to share across threads. Each call to
/// [`Self::parse`] allocates a fresh tree-sitter `Parser`, which is
/// trivial relative to the cost of parsing.
#[derive(Debug, Default, Clone, Copy)]
pub struct TypescriptFrontend;

impl TypescriptFrontend {
    /// Construct a new frontend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LanguageFrontend for TypescriptFrontend {
    fn language_name(&self) -> &'static str {
        LANGUAGE_ID
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        FILE_EXTENSIONS
    }

    fn parse(&self, source: &str) -> Result<TreeSitterTree, ParseError> {
        // The trait does not currently carry the file path through to `parse`,
        // so we default to non-TSX. TSX-specific parsing is exposed via
        // [`Self::parse_tsx`] for callers that already know the extension.
        parser::parse_typescript(source, false)
    }

    fn lift(
        &self,
        tree: &TreeSitterTree,
        source: &str,
        store: &mut CpgWriteBatch,
        file_id: FileId,
    ) -> Result<NodeId, LiftError> {
        let root = lift::lift_program(tree, source, store, file_id)?;
        self.run_resolution_passes(store);
        Ok(root)
    }
}

impl TypescriptFrontend {
    /// Parse `source` using the TSX grammar variant.
    ///
    /// Use this when the originating file extension is `.tsx` or `.jsx`;
    /// the TSX grammar accepts a strict superset of the TypeScript grammar
    /// at the cost of a small overhead, so we keep the two paths separate.
    ///
    /// # Errors
    ///
    /// Same as [`LanguageFrontend::parse`] — see [`ParseError`].
    pub fn parse_tsx(&self, source: &str) -> Result<TreeSitterTree, ParseError> {
        parser::parse_typescript(source, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_metadata() {
        let f = TypescriptFrontend::new();
        assert_eq!(f.language_name(), "typescript");
        assert!(f.file_extensions().contains(&"ts"));
        assert!(f.file_extensions().contains(&"tsx"));
        assert!(f.file_extensions().contains(&"jsx"));
        assert!(f.file_extensions().contains(&"mjs"));
    }
}
