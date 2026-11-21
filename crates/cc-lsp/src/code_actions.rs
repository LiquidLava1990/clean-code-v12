//! Code-action surface for the LSP daemon.
//!
//! Phase-11 scope (`OSS_LINTER_DELTA.md` §4 Tooling Gap #1): give every
//! `cc-lsp`-emitted diagnostic at least two editor-driven affordances:
//!
//! 1. A **suppress** quick-fix that inserts a `// cc-allow:RULE_ID` comment
//!    on the line above the diagnostic (preserving the original
//!    indentation). Always offered.
//! 2. A **suggested-rewrite description** quick-fix that surfaces any
//!    `Remediation::SuggestedRewrite` text the rule attached to the
//!    finding. Phase-11 ships this as a non-applicable, disabled
//!    `CodeAction` — no `WorkspaceEdit` yet — so editors render it as a
//!    description-only entry. Real `WorkspaceEdit` emission for
//!    `Remediation::AutoFix(FixProposal::Diff { … })` follows once the
//!    finding-cache is wired (TODO below).
//!
//! The module is intentionally pure: no salsa, no I/O, no `tokio::Mutex`.
//! Building actions from a `Diagnostic` + buffer text is a synchronous
//! function, which keeps the [`crate::server`] handler trivial to test
//! and immune to deadlocks on the analyser mutex.
//!
//! # Suppress-comment language quirk
//!
//! All four Phase-1 frontends (Python, TypeScript, Go, Rust) accept `//`
//! line comments OR `#` line comments — but never both. We pick the
//! comment delimiter from the file extension. Unknown extensions fall
//! back to `//` (the most common form across the supported set).

use std::collections::HashMap;

use cc_finding::{Finding, Remediation};
use tower_lsp::lsp_types::{
    CodeAction, CodeActionContext, CodeActionDisabled, CodeActionKind, CodeActionOrCommand,
    Diagnostic, NumberOrString, Position, Range, TextEdit, Url, WorkspaceEdit,
};

/// Title prefix used for the "suppress this finding" quick-fix.
///
/// Stable so end-users can keybind to the `cc:` prefix in their editor.
pub const SUPPRESS_TITLE_PREFIX: &str = "cc: suppress";

/// Title prefix used for the suggested-rewrite description action.
pub const REWRITE_TITLE_PREFIX: &str = "cc: suggested rewrite";

/// Default comment delimiter when the URI extension is unknown.
const DEFAULT_LINE_COMMENT: &str = "//";

/// Maximum length of an inline rewrite snippet shown in the action title.
///
/// Keeps the editor's quick-fix list tidy on long suggestions.
const REWRITE_TITLE_SNIPPET_BUDGET: usize = 60;

/// Build the code-action response for one document.
///
/// `findings` is the *most recent* finding set computed for `uri` —
/// callers feed it in from the same analyser run that produced the
/// diagnostics the editor is showing. We re-match findings against the
/// `context.diagnostics` LSP sent us (by stable `rule_id` + `range`) so
/// stale findings do not surface stale actions.
///
/// Returns an empty vector when no diagnostic in `context` overlaps the
/// editor cursor `range`, when no matching finding is found, or when the
/// finding carries neither a suppress nor a rewrite affordance.
#[must_use]
pub fn build_code_actions(
    uri: &Url,
    text: &str,
    range: Range,
    context: &CodeActionContext,
    findings: &[Finding],
) -> Vec<CodeActionOrCommand> {
    let mut out: Vec<CodeActionOrCommand> = Vec::new();
    for diagnostic in &context.diagnostics {
        if !ranges_overlap(range, diagnostic.range) {
            continue;
        }
        let Some(rule_id) = rule_id_of(diagnostic) else {
            continue;
        };
        let suppress = build_suppress_action(uri, text, diagnostic, rule_id);
        out.push(CodeActionOrCommand::CodeAction(suppress));
        if let Some(rewrite) = matching_rewrite_action(diagnostic, rule_id, findings) {
            out.push(CodeActionOrCommand::CodeAction(rewrite));
        }
    }
    out
}

/// Build the "suppress this finding" quick-fix.
///
/// The edit inserts a new line above the diagnostic carrying
/// `<INDENT><LINE_COMMENT> cc-allow:RULE_ID` where `INDENT` is the
/// leading whitespace of the diagnostic's start line in `text` (so the
/// suppress comment lines up with the offending statement).
#[must_use]
pub fn build_suppress_action(
    uri: &Url,
    text: &str,
    diagnostic: &Diagnostic,
    rule_id: &str,
) -> CodeAction {
    let comment_prefix = line_comment_for_uri(uri);
    let line_index = usize::try_from(diagnostic.range.start.line).unwrap_or(usize::MAX);
    let indent = leading_indent_for_line(text, line_index);
    let new_text = format!("{indent}{comment_prefix} cc-allow:{rule_id}\n");
    let insert_at = Position {
        line: diagnostic.range.start.line,
        character: 0,
    };
    let edit = TextEdit {
        range: Range {
            start: insert_at,
            end: insert_at,
        },
        new_text,
    };
    let mut changes: HashMap<Url, Vec<TextEdit>> = HashMap::new();
    changes.insert(uri.clone(), vec![edit]);
    CodeAction {
        title: format!("{SUPPRESS_TITLE_PREFIX} {rule_id}"),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diagnostic.clone()]),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            document_changes: None,
            change_annotations: None,
        }),
        command: None,
        is_preferred: Some(false),
        disabled: None,
        data: None,
    }
}

/// Locate the finding matching `diagnostic` and, if it carries a
/// `Remediation::SuggestedRewrite`, build a description-only code-action.
///
/// Phase-11 ships this as a [`CodeActionDisabled`] entry because the
/// `SuggestedRewrite` payload is human-readable prose, not a structural
/// edit — the editor renders it as faded-out text in the lightbulb menu.
fn matching_rewrite_action(
    diagnostic: &Diagnostic,
    rule_id: &str,
    findings: &[Finding],
) -> Option<CodeAction> {
    let finding = find_matching_finding(diagnostic, rule_id, findings)?;
    let rewrite = first_suggested_rewrite(&finding.message.remediation)?;
    let snippet = single_line_snippet(rewrite, REWRITE_TITLE_SNIPPET_BUDGET);
    Some(CodeAction {
        title: format!("{REWRITE_TITLE_PREFIX}: {snippet}"),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diagnostic.clone()]),
        edit: None,
        command: None,
        is_preferred: Some(false),
        disabled: Some(CodeActionDisabled {
            reason: rewrite.clone(),
        }),
        data: None,
    })
}

/// Return the first `Remediation::SuggestedRewrite` payload anywhere in
/// the remediation tree, or `None` if there is no rewrite.
fn first_suggested_rewrite(remediation: &Remediation) -> Option<&String> {
    match remediation {
        Remediation::SuggestedRewrite(text) => Some(text),
        Remediation::Multiple(items) => items.iter().find_map(first_suggested_rewrite),
        _ => None,
    }
}

/// Match a diagnostic back to the finding that produced it.
///
/// We key on `(rule_id, start_line, start_character)` — `cc-lsp` emits
/// at most one diagnostic per (rule, position) tuple per refresh.
fn find_matching_finding<'a>(
    diagnostic: &Diagnostic,
    rule_id: &str,
    findings: &'a [Finding],
) -> Option<&'a Finding> {
    findings.iter().find(|f| {
        if f.rule_id.as_ref() != rule_id {
            return false;
        }
        let pos = &f.location.start;
        let line_zero = pos.line.saturating_sub(1);
        let col_zero = pos.column.saturating_sub(1);
        line_zero == diagnostic.range.start.line && col_zero == diagnostic.range.start.character
    })
}

/// Read the `code` field on `diagnostic` as a stable rule slug.
///
/// `cc-lsp` always sets `code = NumberOrString::String(rule_id)`; this
/// helper degrades gracefully when an upstream extension forwards a
/// numeric or missing code (returns `None`, which suppresses the
/// action — never panics).
fn rule_id_of(diagnostic: &Diagnostic) -> Option<&str> {
    match &diagnostic.code {
        Some(NumberOrString::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// Return the leading whitespace prefix of `line_index` (0-based) in
/// `text`. Empty string if the line is missing or has no indent.
fn leading_indent_for_line(text: &str, line_index: usize) -> String {
    let Some(line) = text.lines().nth(line_index) else {
        return String::new();
    };
    line.chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

/// Pick a line-comment delimiter from the file extension.
///
/// All Phase-1 languages (Python, TS, Go, Rust) use `//` or `#`; we map
/// the few `#`-comment languages explicitly and fall back to `//`.
fn line_comment_for_uri(uri: &Url) -> &'static str {
    let path = uri.path();
    let ext = path
        .rsplit('.')
        .next()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "py" | "pyi" => "#",
        _ => DEFAULT_LINE_COMMENT,
    }
}

/// Squash `text` to a single line capped at `budget` chars (with `…`
/// elision when truncated). Used for code-action titles only.
fn single_line_snippet(text: &str, budget: usize) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c == '\n' { ' ' } else { c })
        .collect();
    let trimmed = flat.trim();
    if trimmed.chars().count() <= budget {
        return trimmed.to_owned();
    }
    let mut out: String = trimmed.chars().take(budget.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Return `true` iff the two ranges share any position (LSP semantics).
fn ranges_overlap(a: Range, b: Range) -> bool {
    !(position_lt(a.end, b.start) || position_lt(b.end, a.start))
}

/// Strict less-than ordering on LSP `Position`s.
fn position_lt(a: Position, b: Position) -> bool {
    (a.line, a.character) < (b.line, b.character)
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use cc_finding::{
        ActionableMessage, Category, CostClaim, Evidence, FindingBuilder, Location, ProbeVersion,
        Remediation, Severity,
    };
    use tower_lsp::lsp_types::{DiagnosticSeverity, NumberOrString};

    fn diag_at(rule_id: &str, line: u32, character: u32) -> Diagnostic {
        Diagnostic {
            range: Range {
                start: Position { line, character },
                end: Position {
                    line,
                    character: character + 4,
                },
            },
            severity: Some(DiagnosticSeverity::WARNING),
            code: Some(NumberOrString::String(rule_id.to_owned())),
            code_description: None,
            source: Some("cc".to_owned()),
            message: "x".to_owned(),
            related_information: None,
            tags: None,
            data: None,
        }
    }

    fn finding_with_rewrite(
        rule_id: &'static str,
        line_one_indexed: u32,
        rewrite: &str,
    ) -> Finding {
        FindingBuilder::new()
            .rule_id(rule_id)
            .category(Category::Shape)
            .location(Location {
                file: Utf8PathBuf::from("src/lib.py"),
                start: cc_finding::Position::new(line_one_indexed, 1, 0),
                end: cc_finding::Position::new(line_one_indexed, 5, 4),
                node_id: None,
                function_qualified_name: None,
            })
            .message(ActionableMessage::new(
                "headline",
                "explanation",
                Remediation::SuggestedRewrite(rewrite.to_owned()),
            ))
            .evidence(Evidence::from_snippet("x"))
            .severity(Severity::Required)
            .confidence(1.0)
            .cost(CostClaim::BlockingDebt { weight: 1 })
            .probe_version(ProbeVersion::new("cc-test", "0.0.0", 1, None))
            .build()
            .expect("test finding builds")
    }

    fn empty_context(diags: Vec<Diagnostic>) -> CodeActionContext {
        CodeActionContext {
            diagnostics: diags,
            only: None,
            trigger_kind: None,
        }
    }

    fn temp_uri(name: &str) -> Url {
        let path = std::env::temp_dir().join(name);
        Url::from_file_path(&path).expect("temp file URL")
    }

    #[test]
    fn build_emits_suppress_and_rewrite_for_matched_finding() {
        let uri = temp_uri("cc_lsp_action_test.py");
        let text = "    pass\n";
        let diag = diag_at("cc.shape.fn_length", 0, 0);
        let finding = finding_with_rewrite(
            "cc.shape.fn_length",
            1,
            "Split this function into smaller helpers.",
        );
        let actions = build_code_actions(
            &uri,
            text,
            diag.range,
            &empty_context(vec![diag.clone()]),
            std::slice::from_ref(&finding),
        );
        assert_eq!(
            actions.len(),
            2,
            "expected suppress + rewrite, got: {actions:?}"
        );
        let titles: Vec<&str> = actions
            .iter()
            .map(|a| match a {
                CodeActionOrCommand::CodeAction(ca) => ca.title.as_str(),
                CodeActionOrCommand::Command(c) => c.title.as_str(),
            })
            .collect();
        assert!(
            titles.iter().any(|t| t.starts_with(SUPPRESS_TITLE_PREFIX)),
            "expected suppress action; got titles {titles:?}"
        );
        assert!(
            titles.iter().any(|t| t.starts_with(REWRITE_TITLE_PREFIX)),
            "expected rewrite action; got titles {titles:?}"
        );
    }

    #[test]
    fn build_returns_empty_when_no_diagnostic_in_context() {
        let uri = temp_uri("cc_lsp_action_empty.py");
        let actions = build_code_actions(
            &uri,
            "",
            Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: 0,
                },
            },
            &empty_context(Vec::new()),
            &[],
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn build_skips_diagnostic_with_unknown_code_kind() {
        let uri = temp_uri("cc_lsp_action_numeric.py");
        let mut diag = diag_at("cc.shape.fn_length", 0, 0);
        diag.code = Some(NumberOrString::Number(42));
        let actions = build_code_actions(&uri, "", diag.range, &empty_context(vec![diag]), &[]);
        assert!(
            actions.is_empty(),
            "numeric diagnostic codes are ignored, not panicking"
        );
    }

    #[test]
    fn suppress_action_inserts_comment_above_with_correct_indent_and_rule_id() {
        let uri = temp_uri("cc_lsp_suppress.py");
        let text = "def f():\n    bad_call()\n";
        // Diagnostic on line index 1 (the indented `bad_call()` line).
        let diag = diag_at("cc.shape.fn_length", 1, 4);
        let action = build_suppress_action(&uri, text, &diag, "cc.shape.fn_length");
        assert_eq!(
            action.title,
            format!("{SUPPRESS_TITLE_PREFIX} cc.shape.fn_length")
        );
        let edit = action.edit.expect("suppress action has WorkspaceEdit");
        let changes = edit.changes.expect("changes map present");
        let edits = changes.get(&uri).expect("edits keyed by uri");
        assert_eq!(edits.len(), 1, "exactly one TextEdit");
        let te = &edits[0];
        assert_eq!(
            te.range.start,
            Position {
                line: 1,
                character: 0
            }
        );
        assert_eq!(
            te.range.end,
            Position {
                line: 1,
                character: 0
            }
        );
        assert_eq!(te.new_text, "    # cc-allow:cc.shape.fn_length\n");
    }

    #[test]
    fn suppress_action_uses_double_slash_for_rust_files() {
        let uri = temp_uri("cc_lsp_suppress.rs");
        let text = "fn f() {\n    bad_call();\n}\n";
        let diag = diag_at("cc.shape.fn_length", 1, 4);
        let action = build_suppress_action(&uri, text, &diag, "cc.shape.fn_length");
        let edit = action.edit.expect("edit present");
        let edits = edit.changes.unwrap();
        let te = &edits.values().next().unwrap()[0];
        assert_eq!(te.new_text, "    // cc-allow:cc.shape.fn_length\n");
    }

    #[test]
    fn leading_indent_handles_tabs_and_missing_lines() {
        assert_eq!(leading_indent_for_line("\t\thi", 0), "\t\t");
        assert_eq!(leading_indent_for_line("nope", 5), "");
        assert_eq!(leading_indent_for_line("", 0), "");
    }

    #[test]
    fn first_rewrite_walks_multiple_remediations() {
        let r = Remediation::Multiple(vec![
            Remediation::doc_link("https://example.invalid"),
            Remediation::SuggestedRewrite("rewrite me".to_owned()),
        ]);
        assert_eq!(
            first_suggested_rewrite(&r).map(String::as_str),
            Some("rewrite me")
        );
    }

    #[test]
    fn rewrite_returns_none_when_finding_has_no_rewrite() {
        let uri = temp_uri("cc_lsp_no_rewrite.py");
        let diag = diag_at("cc.shape.fn_length", 0, 0);
        // Build a finding with a doc-link only — no rewrite payload.
        let finding = FindingBuilder::new()
            .rule_id("cc.shape.fn_length")
            .category(Category::Shape)
            .location(Location {
                file: Utf8PathBuf::from("src/lib.py"),
                start: cc_finding::Position::new(1, 1, 0),
                end: cc_finding::Position::new(1, 5, 4),
                node_id: None,
                function_qualified_name: None,
            })
            .message(ActionableMessage::new(
                "h",
                "e",
                Remediation::doc_link("https://example.invalid/r"),
            ))
            .evidence(Evidence::from_snippet("x"))
            .severity(Severity::Required)
            .confidence(1.0)
            .cost(CostClaim::BlockingDebt { weight: 1 })
            .probe_version(ProbeVersion::new("cc-test", "0.0.0", 1, None))
            .build()
            .expect("build");
        let actions = build_code_actions(
            &uri,
            "x = 1\n",
            diag.range,
            &empty_context(vec![diag]),
            std::slice::from_ref(&finding),
        );
        // Suppress fires; rewrite does not.
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn snippet_truncates_long_text_with_ellipsis() {
        let long = "a".repeat(200);
        let s = single_line_snippet(&long, 10);
        assert_eq!(s.chars().count(), 10);
        assert!(s.ends_with('…'));
    }

    #[test]
    fn snippet_collapses_newlines() {
        assert_eq!(single_line_snippet("line1\nline2", 80), "line1 line2");
    }
}
