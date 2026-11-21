//! `cc.bug.furb_implicit_int_str_concat` — Python `"foo" "bar"`
//! (implicit string concatenation). The two literals fuse into a single
//! string at parse time, which is sometimes intentional for line
//! continuation but is more often a missed comma in a list / call /
//! tuple.
//!
//! Mirrors ruff `ISC001` (single-line-implicit-string-concatenation).
//!
//! Phase-10 detector: scan every `.py` file once. For each line, walk
//! through string literals and flag any two adjacent literals separated
//! only by whitespace on the same line. Skips multiline triple-quoted
//! literals — those are handled by ISC002, out of scope for this probe.
//!
//! Severity: `Required`. Confidence 0.95 — the pattern is concrete; the
//! rare intentional uses (deliberately broken-up long literals) can be
//! suppressed per-line.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.furb_implicit_int_str_concat`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FurbImplicitIntStrConcatRule;

impl Rule for FurbImplicitIntStrConcatRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.furb_implicit_int_str_concat"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "Python `\"foo\" \"bar\"` — implicit string concat (often a missing comma)"
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
        if line_has_implicit_concat(line) {
            out.push(emit(path.clone(), line_idx + 1, line));
        }
    }
}

/// True iff the line has two adjacent string literals separated only by
/// whitespace. Skips lines containing triple-quoted literals (out of
/// scope: ruff ISC002 handles multiline).
fn line_has_implicit_concat(line: &str) -> bool {
    if line.contains("\"\"\"") || line.contains("'''") {
        return false;
    }
    let bytes = line.as_bytes();
    let mut idx = 0;
    let mut last_end: Option<usize> = None;
    while idx < bytes.len() {
        match bytes[idx] {
            b'#' => return false,
            b'"' | b'\'' => match step_through_literal(line, idx, last_end) {
                LiteralStep::Concat => return true,
                LiteralStep::Bail => return false,
                LiteralStep::Advance(end) => {
                    last_end = Some(end);
                    idx = end + 1;
                }
            },
            _ => idx += 1,
        }
    }
    false
}

enum LiteralStep {
    Concat,
    Bail,
    Advance(usize),
}

/// Process a string literal starting at `idx`. If a previous literal
/// closed at `last_end` and only whitespace separates them, the line
/// has an implicit concat — return [`LiteralStep::Concat`]. Otherwise
/// return the closing index so the caller resumes scanning past it.
fn step_through_literal(line: &str, idx: usize, last_end: Option<usize>) -> LiteralStep {
    let Some(end) = scan_string_literal(line, idx) else {
        return LiteralStep::Bail;
    };
    if let Some(prev_end) = last_end {
        if only_whitespace_between(line, prev_end + 1, idx) {
            return LiteralStep::Concat;
        }
    }
    LiteralStep::Advance(end)
}

/// Scan from `start` (where `bytes[start]` is `"` or `'`) to the
/// matching unescaped quote. Returns the closing-quote index.
fn scan_string_literal(line: &str, start: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    let quote = bytes[start];
    let mut idx = start + 1;
    while idx < bytes.len() {
        let c = bytes[idx];
        if c == b'\\' {
            idx += 2;
            continue;
        }
        if c == quote {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

fn only_whitespace_between(line: &str, from: usize, to: usize) -> bool {
    if to <= from {
        return false;
    }
    line.as_bytes()[from..to]
        .iter()
        .all(|b| *b == b' ' || *b == b'\t')
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
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.furb_implicit_int_str_concat",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "implicit string concat (`\"a\" \"b\"`) — likely missing comma".into(),
        explanation: "Two adjacent string literals separated only by \
             whitespace fuse into a single string at parse time \
             (`\"foo\" \"bar\"` -> `\"foobar\"`). The pattern is \
             occasionally intentional for breaking up long literals, but \
             far more often it's a dropped comma inside a list / call / \
             tuple — `[\"foo\" \"bar\"]` was meant as `[\"foo\", \
             \"bar\"]` and is now a single-element list."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add the missing comma if the two strings were meant as \
             separate elements. If the implicit concat is intentional \
             (long literal split for line length), use an explicit `+` \
             or a parenthesised group with one literal per line so the \
             intent is unmistakable. Mirrors ruff ISC001."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
