//! Tree-sitter parsing for Rust source.
//!
//! Wraps `tree_sitter::Parser` with our public [`ParseError`] type. The
//! grammar is loaded statically from `tree_sitter_rust::LANGUAGE` — if the
//! grammar version is incompatible with our `tree-sitter` runtime, the
//! mismatch surfaces as [`cc_frontend::ParseErrorKind::GrammarMissing`] with
//! actionable guidance.

use cc_cpg::Position;
use cc_frontend::{ParseError, ParseErrorKind, TreeSitterTree};
use tree_sitter::Parser;

use crate::LANGUAGE_ID;

/// Parse Rust source into a [`TreeSitterTree`].
///
/// # Errors
///
/// - [`ParseErrorKind::GrammarMissing`] if the bundled grammar fails to load
///   (almost always a version mismatch between `tree-sitter` and
///   `tree-sitter-rust`).
/// - [`ParseErrorKind::EncodingError`] if the parser refuses the source
///   bytes (the only documented cause is `len > i32::MAX`).
pub(crate) fn parse_rust(source: &str) -> Result<TreeSitterTree, ParseError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|e| {
            ParseError::new(
                LANGUAGE_ID,
                &format!("set_language failed: {}", err_kind(&e)),
                Position::start_of_file(),
                ParseErrorKind::GrammarMissing,
            )
        })?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        ParseError::new(
            LANGUAGE_ID,
            excerpt(source),
            Position::start_of_file(),
            ParseErrorKind::EncodingError,
        )
    })?;
    Ok(TreeSitterTree::new(tree, LANGUAGE_ID))
}

/// Truncated, secret-safe representation of an error type — only the type
/// name is logged, never any borrowed value (S10 hygiene).
fn err_kind<E>(_: &E) -> &'static str {
    std::any::type_name::<E>()
}

/// Produce a small leading excerpt (≤ 80 bytes) from `source` without
/// splitting a UTF-8 codepoint. Caller-side `ParseError::new` re-truncates
/// defensively so this is best-effort.
fn excerpt(source: &str) -> &str {
    let max = source.len().min(80);
    let mut end = max;
    while end > 0 && !source.is_char_boundary(end) {
        end -= 1;
    }
    &source[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_source() {
        let tree = parse_rust("").expect("empty parse");
        assert_eq!(tree.root_node().kind(), "source_file");
    }

    #[test]
    fn parses_simple_function() {
        let tree = parse_rust("fn f() {}\n").expect("parse");
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn partial_parse_still_returns_tree() {
        // Tree-sitter is error-resilient — it still produces a tree with
        // ERROR nodes embedded.
        let tree = parse_rust("fn f( {}\n").expect("partial parse");
        assert!(tree.root_node().has_error());
    }
}
