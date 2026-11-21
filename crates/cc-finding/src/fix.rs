//! Fix proposals — the "how to repair" side of every Finding.

use serde::{Deserialize, Serialize};

use crate::location::Position;

/// A half-open `[start, end)` source range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// Inclusive start.
    pub start: Position,
    /// Exclusive end.
    pub end: Position,
}

/// A single text edit replacing the bytes in `range` with `new_text`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextEdit {
    /// Range to replace.
    pub range: Range,
    /// Replacement text.
    pub new_text: String,
}

/// Behavioural-safety classification of a [`FixProposal`] (Ruff model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FixSafety {
    /// Behaviour-preserving with ≥ 99.9 % confidence (purely syntactic,
    /// scoped). Auto-applied by `ccv12 fix`.
    Safe,
    /// May change behaviour in edge cases — human must confirm.
    /// Surfaced but never applied without `ccv12 fix --unsafe`.
    Unsafe,
}

/// Codemod backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodemodEngine {
    /// Walk-the-AST style structural search/replace via comby.
    Comby,
    /// Tree-sitter based pattern matching via ast-grep.
    AstGrep,
}

/// Scope of a codemod application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CodemodScope {
    /// Single function body.
    Function,
    /// Single file.
    File,
    /// Whole project — heaviest scope, requires explicit opt-in.
    Project,
}

/// Stable hash of the LLM prompt that produced a rewrite, used for
/// caching and replay. Hex-encoded SHA-256 string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PromptHash(pub String);

/// A repair the kernel proposes for a Finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FixProposal {
    /// Concrete machine-applicable diff.
    Diff {
        /// Edits to apply atomically.
        edits: Vec<TextEdit>,
        /// Behavioural-safety classification.
        safety: FixSafety,
        /// 0..=1 confidence the fix is correct.
        confidence: f32,
    },
    /// Codemod via comby / ast-grep.
    Codemod {
        /// Backend engine.
        engine: CodemodEngine,
        /// Search pattern in engine syntax.
        pattern: String,
        /// Replacement template in engine syntax.
        replacement: String,
        /// Application scope.
        scope: CodemodScope,
    },
    /// LLM-proposed rewrite — never auto-applied; human review required.
    LlmRewrite {
        /// Original code that was sent to the model.
        original: String,
        /// Proposed replacement returned by the model.
        proposed: String,
        /// Why the model thinks the rewrite is an improvement.
        rationale: String,
        /// Stable hash of the prompt for caching + replay.
        prompt_hash: PromptHash,
    },
}

impl FixProposal {
    /// Return `true` if the kernel may auto-apply this fix.
    #[must_use]
    pub const fn is_auto_applicable(&self) -> bool {
        matches!(
            self,
            Self::Diff {
                safety: FixSafety::Safe,
                ..
            }
        )
    }
}
