//! Thin wrapper around `tree_sitter::Tree`.
//!
//! Frontends should never expose raw `tree_sitter::Tree` to consumers — the
//! kernel must remain agnostic of the parsing backend so we can swap to a
//! native Rust parser later without rippling through the API surface.

use tree_sitter::{Node as TsNode, Tree as RawTree, TreeCursor};

/// Stable identifier for the language a tree was parsed with.
///
/// Matches `LanguageFrontend::language_name()` of the producing frontend so
/// tooling can route a tree back to its frontend without a registry lookup.
pub type LanguageId = &'static str;

/// Owned tree-sitter parse tree, tagged with its producing language.
#[derive(Debug)]
pub struct TreeSitterTree {
    inner: RawTree,
    language: LanguageId,
}

impl TreeSitterTree {
    /// Wrap a raw tree-sitter `Tree` with its producing language id.
    ///
    /// Frontends call this from their `parse` impl. The wrapper takes
    /// ownership; downstream consumers borrow nodes via [`Self::root_node`]
    /// or walk via [`Self::walk`].
    #[must_use]
    pub fn new(inner: RawTree, language: LanguageId) -> Self {
        Self { inner, language }
    }

    /// Root node of the parsed tree.
    #[must_use]
    pub fn root_node(&self) -> TsNode<'_> {
        self.inner.root_node()
    }

    /// Owned cursor positioned at the root.
    #[must_use]
    pub fn walk(&self) -> TreeCursor<'_> {
        self.inner.walk()
    }

    /// Stable language id. Matches `LanguageFrontend::language_name`.
    #[must_use]
    pub const fn language_id(&self) -> LanguageId {
        self.language
    }

    /// Borrow the underlying tree-sitter tree.
    ///
    /// Escape hatch for in-tree frontends only — external code should
    /// prefer [`Self::root_node`] / [`Self::walk`].
    #[must_use]
    pub const fn raw(&self) -> &RawTree {
        &self.inner
    }
}
