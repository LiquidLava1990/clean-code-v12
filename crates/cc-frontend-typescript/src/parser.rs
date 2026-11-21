//! Tree-sitter parsing for TypeScript / TSX source.
//!
//! Wraps `tree_sitter::Parser` with our public [`ParseError`] type. Two
//! grammar variants are supported: `LANGUAGE_TYPESCRIPT` for the standard
//! TypeScript / JavaScript surface and `LANGUAGE_TSX` for `.tsx` / `.jsx`
//! files where JSX is enabled.

use cc_cpg::Position;
use cc_frontend::{ParseError, ParseErrorKind, TreeSitterTree};
use tree_sitter::Parser;

use crate::LANGUAGE_ID;

/// Parse TypeScript or TSX source into a [`TreeSitterTree`].
///
/// Set `tsx = true` to enable the JSX grammar; pass `false` for plain
/// TypeScript / JavaScript. The choice is per-source because `.tsx` and
/// `.ts` parse with different grammars.
///
/// # Errors
///
/// - [`ParseErrorKind::GrammarMissing`] if the bundled grammar fails to
///   load (almost always a version mismatch between `tree-sitter` and
///   `tree-sitter-typescript`).
/// - [`ParseErrorKind::EncodingError`] if the parser refuses the source
///   bytes (the only documented cause is `len > i32::MAX`).
pub(crate) fn parse_typescript(source: &str, tsx: bool) -> Result<TreeSitterTree, ParseError> {
    let mut parser = Parser::new();
    let language = if tsx {
        tree_sitter_typescript::LANGUAGE_TSX
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT
    };
    parser.set_language(&language.into()).map_err(|e| {
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

/// True if `extension` (no leading `.`, lowercase) selects the TSX grammar.
///
/// Public so callers that own the file path can route correctly without
/// re-implementing the mapping.
#[must_use]
pub fn is_tsx_extension(extension: &str) -> bool {
    matches!(extension, "tsx" | "jsx")
}

/// Truncated, secret-safe representation of an error type — only the
/// type name is logged, never any borrowed value (S10 hygiene).
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
        let tree = parse_typescript("", false).expect("empty parse");
        assert_eq!(tree.root_node().kind(), "program");
    }

    #[test]
    fn parses_simple_function() {
        let tree = parse_typescript("function f(): void {}\n", false).expect("parse");
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn partial_parse_still_returns_tree() {
        let tree = parse_typescript("function f(", false).expect("partial parse");
        assert!(tree.root_node().has_error());
    }

    #[test]
    fn parses_tsx_with_jsx() {
        let tree = parse_typescript("const x = <Foo bar={1} />;\n", true).expect("tsx parse");
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn tsx_extension_routing() {
        assert!(is_tsx_extension("tsx"));
        assert!(is_tsx_extension("jsx"));
        assert!(!is_tsx_extension("ts"));
        assert!(!is_tsx_extension("js"));
    }
}
