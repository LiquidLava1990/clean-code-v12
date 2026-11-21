//! `cc.test.pt_assert_in_finally` — `assert ...` inside a `finally:`
//! block. If the `try` body raises, the assertion still runs but pytest
//! reports the original exception instead of the assertion failure —
//! the assertion is silently swallowed.
//!
//! Mirrors ruff PT017. The motivation: a `finally:` block is the wrong
//! place for an assertion. If the `try:` body raises, the original
//! exception is the failure mode, the `finally:` assertion adds noise,
//! and if the assertion itself fails the original cause is lost.
//!
//! Phase-10 source-byte detector: `.py` files only. Find every
//! `finally:` line, then walk forward at one deeper indent collecting
//! lines that start with `assert ` until the indent unwinds.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TestDesignFindingBlueprint,
};

/// Family-28 probe `cc.test.pt_assert_in_finally`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PtAssertInFinallyRule;

const MAX_BODY_LOOKAHEAD: usize = 80;

impl Rule for PtAssertInFinallyRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.pt_assert_in_finally"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "`assert ...` inside `finally:` swallows the original exception"
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
            if !is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
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
    let lines: Vec<&str> = text.lines().collect();
    for idx in 0..lines.len() {
        if !is_finally_header(lines[idx]) {
            continue;
        }
        let header_indent = leading_indent(lines[idx]);
        for assert_idx in find_asserts_in_block(&lines, idx + 1, header_indent) {
            out.push(emit(path.clone(), assert_idx + 1, lines[assert_idx]));
        }
    }
}

fn is_finally_header(line: &str) -> bool {
    let trimmed = line.trim_start();
    let trailing = trimmed.trim_end();
    trailing == "finally:"
}

fn leading_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Walk forward from `start` while the indent strictly exceeds
/// `header_indent`. Yield every line whose trimmed prefix is `assert `.
fn find_asserts_in_block(lines: &[&str], start: usize, header_indent: usize) -> Vec<usize> {
    let cap = (start + MAX_BODY_LOOKAHEAD).min(lines.len());
    let mut hits = Vec::new();
    for idx in start..cap {
        let line = lines[idx];
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_indent(line);
        if indent <= header_indent {
            break;
        }
        if trimmed.starts_with("assert ") || trimmed == "assert" {
            hits.push(idx);
        }
    }
    hits
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.pt_assert_in_finally",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "`assert` inside `finally:` block".into(),
        explanation: "An `assert` inside `finally:` swallows the original \
             exception from the `try:` body. If the `try:` raises, the \
             test fails with the unrelated original error instead of the \
             assertion message; if the assertion itself fails first, it \
             can mask a real bug. Either move the assertion outside the \
             `try` block, or replace it with a recorded result inspected \
             after the block returns."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Move the assertion out of `finally:`. If you need it to run \
             on every path, record state into a variable inside the \
             `try`/`except` and assert on that variable after the \
             `try`/`finally` completes."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
