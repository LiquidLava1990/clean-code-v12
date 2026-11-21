//! `cc.test.pt_raises_simple_block` — `with pytest.raises(...):` body
//! has more than one statement, so the first statement might raise the
//! expected exception while later statements are dead code.
//!
//! Mirrors ruff PT012. The motivation: a multi-statement body inside a
//! `pytest.raises` block hides intent — only one of the statements is
//! the "act" the test asserts on, but the test still passes if any of
//! them raises. That is a false-positive farm.
//!
//! Phase-10 source-byte detector: `.py` files only. Find every
//! `with pytest.raises(...):` line, count non-blank / non-comment lines
//! at one deeper indent level until the indent unwinds, fire when the
//! count exceeds `MAX_BODY_STATEMENTS`.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TestDesignFindingBlueprint,
};

/// Family-28 probe `cc.test.pt_raises_simple_block`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PtRaisesSimpleBlockRule;

const MAX_BODY_STATEMENTS: usize = 1;
const MAX_BODY_LOOKAHEAD: usize = 80;

const NEEDLES: &[&str] = &["with pytest.raises(", "with raises("];

impl Rule for PtRaisesSimpleBlockRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.pt_raises_simple_block"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "`with pytest.raises(...):` body has more than one statement"
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
        if !is_pytest_raises_with(lines[idx]) {
            continue;
        }
        let header_indent = leading_indent(lines[idx]);
        let count = count_body_statements(&lines, idx + 1, header_indent);
        if count > MAX_BODY_STATEMENTS {
            out.push(emit(path.clone(), idx + 1, lines[idx], count));
        }
    }
}

fn is_pytest_raises_with(line: &str) -> bool {
    let trimmed = line.trim_start();
    if !trimmed.ends_with(':') {
        return false;
    }
    NEEDLES.iter().any(|n| trimmed.contains(*n))
}

fn leading_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Walk forward from `start` while the indent strictly exceeds
/// `header_indent`. Count each non-blank, non-comment line as a
/// statement.
fn count_body_statements(lines: &[&str], start: usize, header_indent: usize) -> usize {
    let cap = (start + MAX_BODY_LOOKAHEAD).min(lines.len());
    let mut count = 0usize;
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
        count += 1;
    }
    count
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, count: usize) -> Finding {
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
        rule_id: "cc.test.pt_raises_simple_block",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`pytest.raises` block has {count} statements (expected 1)"),
        explanation: "A `with pytest.raises(...):` block should contain exactly \
             one statement — the call you expect to raise. Multiple \
             statements pass the test if any of them raises, so the \
             assertion fires for the wrong reason and you cannot tell \
             from the failure message which line was the act-under-test."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Move every set-up statement before the `with` block. Keep \
             only the single call you want to assert raises inside the \
             block. If the set-up itself can raise, split it into its \
             own test."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
