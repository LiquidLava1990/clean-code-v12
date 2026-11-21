//! `cc.bug.assert_with_tuple` — `assert (x, y)`. A non-empty tuple is
//! always truthy, so the assertion never fails — silently masking the
//! intended check.
//!
//! Mirrors ruff `B011` / `F631` (assert-on-non-empty-tuple).
//!
//! Phase-9 detector: scan every Python file once for `assert (` lines.
//! Walk paren depth from the open paren; if a top-level `,` appears
//! before the close paren, the operand is a tuple. Skip lines that
//! parenthesise a single expression (`assert (x and y)`).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.assert_with_tuple`.
#[derive(Debug, Default, Clone, Copy)]
pub struct AssertWithTupleRule;

impl Rule for AssertWithTupleRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.assert_with_tuple"
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
        "Python `assert (x, y)` — tuple is always truthy, assertion is a no-op"
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
            // Note: ruff B011 explicitly DOES fire in tests — the bug
            // is the same. Skip rule-pack source so we don't self-flag.
            if looks_like_rule_pack_source(&path) {
                continue;
            }
            // We still skip auto-generated test fixtures via the
            // helper to keep the noise floor low; tests that genuinely
            // want this pattern can disable per-line.
            if is_test_file_path(&path) {
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
        let trimmed = line.trim_start();
        if !trimmed.starts_with("assert ") && !trimmed.starts_with("assert(") {
            continue;
        }
        if line_is_tuple_assert(trimmed) {
            out.push(emit(path.clone(), line_idx + 1, line));
        }
    }
}

/// True iff the assert operand is a tuple — a top-level `,` appears
/// inside the outer parens before the close paren.
fn line_is_tuple_assert(trimmed: &str) -> bool {
    let after = trimmed
        .strip_prefix("assert ")
        .or_else(|| trimmed.strip_prefix("assert"))
        .map(str::trim_start)
        .unwrap_or(trimmed);
    if !after.starts_with('(') {
        return false;
    }
    let bytes = after.as_bytes();
    let mut depth: i32 = 0;
    for (idx, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    // Outer paren closed. Anything past this is the
                    // assert's optional message — `assert (x, y), "msg"`
                    // already counts as a tuple operand we want to flag.
                    return false;
                }
            }
            b',' if depth == 1 => {
                // A top-level comma inside the outer parens — tuple.
                // But guard against `assert (cond), "msg"` where the
                // comma is OUTSIDE the parens; in that case depth was
                // already 0 when we hit `,` and we returned false.
                let _ = idx;
                return true;
            }
            _ => {}
        }
    }
    false
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.assert_with_tuple",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "`assert (x, y)` — non-empty tuple is always truthy".into(),
        explanation: "Python evaluates the parenthesised operand as a \
             tuple expression: `(x, y)`. Any non-empty tuple is truthy, \
             so the assertion never fails — even when both `x` and `y` \
             are false. The check is silently dead code."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "If both checks must hold, drop the parens or use `and`: \
             `assert x and y`. If the second item is the assertion \
             message, write `assert x, \"reason\"` (no parens around \
             the condition)."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
