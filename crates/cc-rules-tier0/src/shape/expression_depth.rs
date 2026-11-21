//! Tier-0 forever rule R-EXPRESSION-DEPTH.
//!
//! Flag a function whose body contains a single expression with
//! operator nesting depth exceeding [`MAX_DEPTH`]. Sonar S1067 caps at
//! 6: deeper expressions force the reader into a parser stack.
//!
//! The CPG does not yet emit `BinaryOp` nodes, so this probe falls back
//! to bracket-nesting depth on a per-line basis. We count `(`, `[`, `{`
//! as opens and `)`, `]`, `}` as closes; the max nesting level reached
//! on any single source line is the score.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, byte_window, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, Tier0FindingBlueprint,
};

/// Threshold cited from Sonar S1067 (default 6).
// TODO(W2): wire ctx.config thresholds
const MAX_DEPTH: u32 = 6;

/// Tier-0 forever rule R-EXPRESSION-DEPTH.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExpressionDepthRule;

impl Rule for ExpressionDepthRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.expression_depth"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "expression nests operators deeper than 6 levels"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let range = range_prop(ctx.batch, id, "range")?;
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return None;
    }
    let body = byte_window(bytes, range.start.offset, range.end.offset);
    let depth = max_bracket_depth_per_line(body);
    if depth <= MAX_DEPTH {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = depth.saturating_sub(MAX_DEPTH);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.expression_depth",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "function `{name}` has an expression nested {depth} levels deep (threshold {MAX_DEPTH})"
        ),
        explanation: format!(
            "Deeply nested expressions force the reader into a parser stack. `{name}` \
             reaches depth {depth}; the Tier-0 ceiling is {MAX_DEPTH}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Extract sub-expressions into named local bindings; build the result \
             bottom-up as a sequence of well-named intermediate values."
                .into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

/// Max bracket-nesting depth on any single line of `body`. We count
/// `(`, `[`, `{` as opens and `)`, `]`, `}` as closes. Naively ignores
/// strings / comments — false positives possible for files with heavy
/// string literals containing brackets, but the per-line ceiling
/// usually still fires only on real expression depth.
fn max_bracket_depth_per_line(body: &[u8]) -> u32 {
    let text = std::str::from_utf8(body).unwrap_or("");
    let mut max_depth: u32 = 0;
    for line in text.lines() {
        let depth = max_depth_on_line(line);
        if depth > max_depth {
            max_depth = depth;
        }
    }
    max_depth
}

fn max_depth_on_line(line: &str) -> u32 {
    let mut depth: u32 = 0;
    let mut max_depth: u32 = 0;
    let mut in_string: Option<char> = None;
    let mut prev: char = ' ';
    for ch in line.chars() {
        if let Some(quote) = in_string {
            if ch == quote && prev != '\\' {
                in_string = None;
            }
            prev = ch;
            continue;
        }
        match ch {
            '"' | '\'' => in_string = Some(ch),
            '(' | '[' | '{' => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    max_depth = depth;
                }
            }
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        prev = ch;
    }
    max_depth
}
