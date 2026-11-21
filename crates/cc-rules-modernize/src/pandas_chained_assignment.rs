//! `cc.modernize.pandas_chained_assignment` — `df[col][row] = value`
//! (chained subscript assignment). Pandas 2.x deprecates the pattern:
//! the inner `df[col]` may return a copy or a view depending on shape,
//! so the write either updates the frame or silently writes to a
//! throwaway copy and emits a `SettingWithCopyWarning`.
//!
//! Mirrors ruff `PD901` (chained-assignment).
//!
//! Phase-10 detector: scan every `.py` file once for assignments whose
//! left-hand side has two consecutive subscripts (`name[...][...] =`).
//! The first identifier must look DataFrame-shaped (lowercase Python
//! identifier, not `self`/`cls` to skip object-attribute scenarios).
//!
//! Severity: `Required`. Confidence 0.85 — the LHS shape is concrete
//! and false positives are rare (numpy / dict-of-dicts uses are valid
//! but written this way only intentionally).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.pandas_chained_assignment`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PandasChainedAssignmentRule;

impl Rule for PandasChainedAssignmentRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.pandas_chained_assignment"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "pandas chained subscript assignment `df[col][row] = ...` triggers SettingWithCopyWarning"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
                continue;
            }
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (line_idx, line) in text.lines().enumerate() {
        if line_is_chained_subscript_assignment(line) {
            out.push(emit(path.clone(), line_idx + 1, line));
        }
    }
}

/// True iff `line` looks like `<ident>[ ... ][ ... ] = <rhs>`. We
/// require the assignment operator to follow the second close bracket
/// (with optional whitespace) and to be a real `=` (not `==`, `!=`,
/// `<=`, `>=`, `+=`, `-=`, `*=`, `/=`).
fn line_is_chained_subscript_assignment(line: &str) -> bool {
    let trimmed = line.trim_start();
    let bytes = trimmed.as_bytes();
    let Some(ident_end) = leading_identifier_end(trimmed) else {
        return false;
    };
    let ident = &trimmed[..ident_end];
    if ident == "self" || ident == "cls" {
        return false;
    }
    if bytes.get(ident_end).copied() != Some(b'[') {
        return false;
    }
    let Some(first_close) = match_bracket(trimmed, ident_end) else {
        return false;
    };
    if bytes.get(first_close + 1).copied() != Some(b'[') {
        return false;
    }
    let Some(second_close) = match_bracket(trimmed, first_close + 1) else {
        return false;
    };
    has_assignment_after(trimmed, second_close + 1)
}

fn leading_identifier_end(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return None;
    }
    let mut idx = 1;
    while idx < bytes.len() && (bytes[idx].is_ascii_alphanumeric() || bytes[idx] == b'_') {
        idx += 1;
    }
    Some(idx)
}

fn match_bracket(line: &str, open_idx: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    if bytes.get(open_idx).copied() != Some(b'[') {
        return None;
    }
    let mut depth: i32 = 0;
    for (rel, &b) in bytes.iter().enumerate().skip(open_idx) {
        match b {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rel);
                }
            }
            _ => {}
        }
    }
    None
}

fn has_assignment_after(line: &str, idx: usize) -> bool {
    let bytes = line.as_bytes();
    let mut cursor = idx;
    while cursor < bytes.len() && bytes[cursor] == b' ' {
        cursor += 1;
    }
    let Some(&first) = bytes.get(cursor) else {
        return false;
    };
    if first != b'=' {
        return false;
    }
    let next = bytes.get(cursor + 1).copied();
    next != Some(b'=') && next != Some(b'!')
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let line_no_u32 = u32::try_from(line_no).unwrap_or(u32::MAX);
    let pos = Position::new(line_no_u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.pandas_chained_assignment",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "`df[col][row] = value` — chained pandas assignment is undefined".into(),
        explanation: "Pandas 2.x deprecates chained subscript assignment. \
             The first `df[col]` may return either a copy or a view of the \
             underlying frame depending on dtype, alignment, and \
             contiguity — pandas itself does not promise which. The \
             assignment then either updates the frame or silently writes \
             to a throwaway copy and emits a `SettingWithCopyWarning`. \
             The next read of `df[col][row]` may or may not reflect the \
             write."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Use `.loc` (label-based) or `.iloc` (positional) for the \
             whole index path: `df.loc[row, col] = value`. The single \
             indexer is guaranteed to address the underlying frame, not \
             a copy. For boolean masks, prefer `df.loc[mask, col] = \
             value`. Mirrors ruff PD901."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
