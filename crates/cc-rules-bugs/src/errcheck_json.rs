//! `cc.bug.errcheck_json` — Go `json.Marshal` / `json.Unmarshal`
//! whose returned `error` is silently dropped.
//!
//! Both functions can fail at runtime: `Marshal` rejects channels,
//! cyclic graphs, and types whose `MarshalJSON` raises; `Unmarshal`
//! rejects malformed payloads. Discarding the error means the program
//! continues with a zero-valued result that is not what the caller
//! thinks they have.
//!
//! OSS source: golangci `errchkjson`.
//!
//! Phase-9 source-byte heuristic: `.go` files only. Detect lines whose
//! left-hand side discards the second return value of `json.Marshal` /
//! `json.Unmarshal` — `_ = json.Marshal(...)`,
//! `b, _ := json.Marshal(...)`, or a bare expression statement
//! `json.Marshal(x)` (no assignment). Skip `_test.go` for safety.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, looks_like_rule_pack_source, BugFindingBlueprint};

/// Family-3 probe R-ERRCHECK-JSON.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErrcheckJsonRule;

const JSON_CALLS: &[&str] = &["json.Marshal(", "json.MarshalIndent(", "json.Unmarshal("];

impl Rule for ErrcheckJsonRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.errcheck_json"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "json.Marshal / json.Unmarshal error return is discarded"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("go") {
                continue;
            }
            if is_go_test_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn is_go_test_path(path: &Utf8PathBuf) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_test.go"))
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let Some(needle) = JSON_CALLS.iter().find(|n| trimmed.contains(*n)) else {
            continue;
        };
        if !discards_error(trimmed, needle) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, line, needle));
    }
}

/// True iff the line discards the `error` return — either via `_` in
/// the LHS, or by being a bare expression statement (no `:=` / `=`).
fn discards_error(trimmed: &str, needle: &str) -> bool {
    let call_idx = match trimmed.find(needle) {
        Some(i) => i,
        None => return false,
    };
    let before = &trimmed[..call_idx];
    let assign_idx = before.find(":=").or_else(|| before.find('='));
    match assign_idx {
        None => is_bare_expression_statement(trimmed, needle),
        Some(end) => lhs_discards_error(&before[..end]),
    }
}

/// A bare `json.Marshal(x)` statement (no assignment) silently drops
/// both returns. Excludes any context where the call is an argument
/// to another call (`log.Print(json.Marshal(x))`) — handled by the
/// outer call's own check.
fn is_bare_expression_statement(trimmed: &str, needle: &str) -> bool {
    if !trimmed.starts_with(needle) {
        return false;
    }
    !trimmed.contains(',')
        || trimmed
            .find(needle)
            .is_some_and(|i| !trimmed[..i].contains(','))
}

/// True iff the LHS — already trimmed of the assignment operator —
/// uses `_` for the second slot.
fn lhs_discards_error(lhs: &str) -> bool {
    let parts: Vec<&str> = lhs.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().any(|p| *p == "_")
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, needle: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    let call = needle.trim_end_matches('(');
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.errcheck_json",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{call}` error return is discarded"),
        explanation: format!(
            "`{call}` returns `(value, error)` — discarding the error \
             means malformed input or unsupported types continue \
             silently with a zero-valued result. The caller's downstream \
             code then operates on `nil` / `\"\"` / a partial struct \
             without knowing the encode/decode failed."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Capture the error: `b, err := {call}(v); if err != nil \
             {{ return ..., fmt.Errorf(\"{call}: %w\", err) }}`. For \
             genuinely-unrecoverable cases (encoding a struct you \
             control), surface the error to a panic at startup, not at \
             a steady-state request boundary."
        )),
        snippet,
        weight: 3,
    })
}
