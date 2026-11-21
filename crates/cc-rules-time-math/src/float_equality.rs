//! `cc.math.float_equality` — flag `==` / `!=` on floating-point values.
//!
//! Phase-3 simplification: the frontend does not currently emit type info
//! on Read / Identifier nodes, so the probe falls back to two textual
//! signals on the `Write` / Identifier surrounding the comparison:
//!
//! 1. Both operands are float **literals** (`literal_kind == "float"`).
//! 2. Either operand is a variable name ending in a ratio / rate /
//!    measurement suffix (`_ratio` / `_rate` / `_pct` / `_percent` /
//!    `_speed` / `_velocity` / `_factor` / `_score`) or a money suffix.
//!
//! Detection is over raw source text inside the surrounding function /
//! file body (the AST does not yet expose `BinaryOp` nodes). This is a
//! deliberate Phase-3 trade-off: we get coverage today and tighten the
//! signal once the frontend ships expression nodes.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_money_name, is_ratio_name, location_from_node,
    scan_decimal_count, TimeMathFindingBlueprint,
};

/// Family-14 probe R-MATH-FLOAT-EQ.
#[derive(Debug, Default, Clone, Copy)]
pub struct FloatEqualityRule;

impl Rule for FloatEqualityRule {
    fn rule_id(&self) -> &'static str {
        "cc.math.float_equality"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "equality comparison on floating-point operands"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            if let Some(mut produced) = scan_file(ctx, node.id) {
                out.append(&mut produced);
            }
        }
        out
    }
}

/// Scan one file's raw source for suspicious `==` / `!=` comparisons.
///
/// Returns `None` when the file has no recorded `path` or no source
/// text. Each emission is at most one finding per source line.
fn scan_file(ctx: &RuleContext<'_>, file_id: NodeId) -> Option<Vec<Finding>> {
    let path = string_prop(ctx.batch, file_id, "path").map(Utf8PathBuf::from)?;
    let bytes = ctx.source.get(path.as_path());
    let text = std::str::from_utf8(bytes).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(reason) = line_triggers(line) {
            if let Some(finding) = emit_for_line(ctx, file_id, line, reason) {
                out.push(finding);
            }
        }
    }
    Some(out)
}

/// Inspect one source line. Returns `Some(reason)` when a float-equality
/// pattern is detected.
fn line_triggers(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }
    if !contains_eq_or_ne(line) {
        return None;
    }
    if has_two_float_literals(line) {
        return Some("two float literals");
    }
    if has_ratio_or_money_identifier(line) {
        return Some("ratio / money identifier");
    }
    None
}

/// Check for `==` / `!=` while excluding the assignment operator `=`.
fn contains_eq_or_ne(line: &str) -> bool {
    line.contains("==") || line.contains("!=")
}

/// Crude two-float-literal detector — at least two decimal numerals
/// with a `.` on the line. Delegates to the shared scanner so depth
/// stays under the Tier-0 nesting ceiling.
fn has_two_float_literals(line: &str) -> bool {
    scan_decimal_count(line) >= 2
}

/// True iff any whitespace-separated token on the line matches a
/// ratio / money identifier suffix.
fn has_ratio_or_money_identifier(line: &str) -> bool {
    line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|tok| !tok.is_empty() && (is_ratio_name(tok) || is_money_name(tok)))
}

/// Build a finding anchored at the file node.
fn emit_for_line(
    ctx: &RuleContext<'_>,
    file_id: NodeId,
    line: &str,
    reason: &'static str,
) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, file_id)?;
    let location = location_from_node(ctx.batch, file_id, path);
    Some(build_finding(TimeMathFindingBlueprint {
        rule_id: "cc.math.float_equality",
        category: Category::Bug,
        severity: Severity::Blocker,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("equality on float operands ({reason})"),
        explanation: format!(
            "`==` / `!=` on floats almost always silently fails: 0.1 + 0.2 != 0.3 \
             in IEEE-754, ratio accumulation drifts after a handful of \
             multiplications, and currency-shaped floats have unrepresentable \
             cents. The line `{}` matches the `{reason}` heuristic.",
            line.trim()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Compare with a tolerance: Python `math.isclose(a, b, rel_tol=1e-9)`, \
             Rust `(a - b).abs() < f64::EPSILON * scale`, or — for currency — \
             use `Decimal` / fixed-point integers (cents) and compare exactly."
                .into(),
        ),
        snippet: line.trim().to_owned(),
        weight: 3,
    }))
}
