//! Error types for the language-frontend pipeline.
//!
//! All variants are `non_exhaustive` so adding a kind in the future is not a
//! breaking API change. Every `Display` impl must answer two questions:
//! **what** failed and **how** to recover. Tests in this module assert that.

use cc_cpg::Position;
use thiserror::Error;

/// Why a tree-sitter parse failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// The tree-sitter grammar for this language is not registered in the
    /// frontend. Fix: register the language in `LanguageRegistry`.
    GrammarMissing,
    /// Tree-sitter produced a tree containing `ERROR` or `MISSING` nodes.
    /// The lifter MAY still consume the partial tree; this variant exists so
    /// downstream callers can choose whether to fail fast or accept partial.
    IncompletePartial,
    /// Source bytes were not valid UTF-8 or contained characters tree-sitter
    /// could not handle (e.g. surrogate halves on Windows).
    EncodingError,
}

impl std::fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GrammarMissing => f.write_str("grammar missing"),
            Self::IncompletePartial => f.write_str("incomplete or partial parse"),
            Self::EncodingError => f.write_str("encoding error"),
        }
    }
}

/// Failure parsing source text into a tree-sitter tree.
///
/// The `source_excerpt` field carries up to 80 bytes of context around the
/// failing position so error messages stay actionable without leaking
/// arbitrary file content into logs.
#[derive(Debug, Clone, Error)]
#[error(
    "parse failed in {language} at line {}: {kind}. \
     near: {source_excerpt:?}. \
     fix: register a tree-sitter grammar for this language or pre-validate the source.",
    .position.line
)]
#[non_exhaustive]
pub struct ParseError {
    /// Language name (matches `LanguageFrontend::language_name`).
    pub language: &'static str,
    /// Up-to-80-byte excerpt around the failure (escaped via `Debug`).
    pub source_excerpt: String,
    /// Best-effort 1-indexed position of the failure.
    pub position: Position,
    /// Why parsing failed.
    pub kind: ParseErrorKind,
}

impl ParseError {
    /// Construct a `ParseError`, truncating `excerpt` to at most 80 bytes
    /// without splitting a UTF-8 codepoint.
    #[must_use]
    pub fn new(
        language: &'static str,
        excerpt: &str,
        position: Position,
        kind: ParseErrorKind,
    ) -> Self {
        Self {
            language,
            source_excerpt: truncate_excerpt(excerpt, 80),
            position,
            kind,
        }
    }
}

/// Failure lifting a tree-sitter node into a CPG node.
///
/// Lift errors are **non-fatal**: the frontend should continue, leaving an
/// `Unresolved` marker node in the CPG. This type exists so post-passes and
/// diagnostics can surface degraded coverage to operators.
#[derive(Debug, Clone, Error)]
#[error(
    "lift failed for `{node_kind}` at line {}: {reason}. \
     fix: extend the frontend's lift table for `{node_kind}` or file an issue with the source excerpt.",
    .position.line
)]
#[non_exhaustive]
pub struct LiftError {
    /// Tree-sitter node kind that the frontend did not know how to handle.
    pub node_kind: String,
    /// 1-indexed source position of the offending node.
    pub position: Position,
    /// Free-form actionable reason. Must include both **what** + **how-to-fix**.
    pub reason: String,
}

impl LiftError {
    /// Construct a `LiftError`. `reason` should be one short clause —
    /// the surrounding `Display` impl already adds the "fix:" guidance.
    #[must_use]
    pub fn new(
        node_kind: impl Into<String>,
        position: Position,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            node_kind: node_kind.into(),
            position,
            reason: reason.into(),
        }
    }
}

/// Failure resolving an identifier to its declaration.
#[derive(Debug, Clone, Error)]
#[error(
    "could not resolve `{identifier}` in scope `{scope}` at line {}. \
     fix: check imports, or add the identifier to the lexical scope chain.",
    .position.line
)]
#[non_exhaustive]
pub struct ResolveError {
    /// Identifier name being resolved.
    pub identifier: String,
    /// Human-readable scope label (e.g. `module:foo` / `fn:bar`).
    pub scope: String,
    /// 1-indexed source position of the identifier.
    pub position: Position,
}

impl ResolveError {
    /// Construct a `ResolveError`.
    #[must_use]
    pub fn new(
        identifier: impl Into<String>,
        scope: impl Into<String>,
        position: Position,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            scope: scope.into(),
            position,
        }
    }
}

/// Top-level error returned by [`crate::FrontendCore::parse_and_lift`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FrontendError {
    /// No frontend was registered for the file's extension.
    #[error(
        "no frontend registered for extension `{extension}` (path: {path}). \
         fix: register a `LanguageFrontend` for this extension via `LanguageRegistry::register`."
    )]
    UnknownExtension {
        /// File extension that had no registered frontend.
        extension: String,
        /// Offending file path (UTF-8 only).
        path: String,
    },

    /// Reading the source file from disk failed.
    #[error(
        "failed to read `{path}`: {source_msg}. \
         fix: verify the file exists, is UTF-8 encoded, and is readable by the current process."
    )]
    Io {
        /// Path that failed to read.
        path: String,
        /// `std::io::Error` message rendered into a string (avoids leaking
        /// borrowed handles into the public error type).
        source_msg: String,
    },

    /// Tree-sitter parse failed.
    #[error(transparent)]
    Parse(#[from] ParseError),

    /// Lift failed at a level the frontend chose to surface as fatal.
    #[error(transparent)]
    Lift(#[from] LiftError),
}

/// Truncate `s` to at most `max_bytes` bytes without splitting a UTF-8 char.
fn truncate_excerpt(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lift_error_message_includes_what_and_how_to_fix() {
        let err = LiftError::new(
            "match_expression",
            Position::new(42, 1, 0),
            "unknown match arm shape",
        );
        let rendered = err.to_string();
        assert!(rendered.contains("match_expression"), "what: {rendered}");
        assert!(rendered.contains("line 42"), "where: {rendered}");
        assert!(rendered.contains("fix:"), "how: {rendered}");
    }

    #[test]
    fn parse_error_truncates_long_excerpts() {
        let big = "x".repeat(1024);
        let err = ParseError::new(
            "python",
            &big,
            Position::start_of_file(),
            ParseErrorKind::IncompletePartial,
        );
        assert!(err.source_excerpt.len() <= 80);
        assert!(err.to_string().contains("incomplete or partial parse"));
    }

    #[test]
    fn truncate_excerpt_respects_utf8_boundary() {
        let s = "ééééééééé"; // 2 bytes per char
        let out = truncate_excerpt(s, 5);
        assert!(out.len() <= 5);
        // Round-trips as valid UTF-8 — String guarantees this.
        let _: &str = &out;
    }
}
