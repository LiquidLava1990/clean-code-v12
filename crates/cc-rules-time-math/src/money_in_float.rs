//! `cc.math.money_in_float` — flag currency-shaped identifiers bound to
//! a floating-point type.
//!
//! Heuristic: every [`NodeKind::Write`] node whose `target` matches a
//! money-style identifier pattern (suffix `_amount` / `_price` / `_cost`
//! / `_balance` / `_total` / `_cents` / `_dollars` / `_fee` / etc., or
//! prefix `currency_` / `money_` / `price_` / `amount_`) is checked.
//!
//! The frontend does not yet emit binding-type info (`type`/`type_name`
//! property), so the probe falls back to scanning the source line for a
//! float literal on the right-hand side. If the assignment looks like
//! `total_amount = 99.99` we flag it; integer literals (`amount_cents = 9999`)
//! are intentionally NOT flagged because they are the recommended fix.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, contains_float_literal, enclosing_file_path, is_float_type, is_money_name,
    location_from_node, TimeMathFindingBlueprint,
};

/// Family-14 probe R-MATH-MONEY-IN-FLOAT.
#[derive(Debug, Default, Clone, Copy)]
pub struct MoneyInFloatRule;

impl Rule for MoneyInFloatRule {
    fn rule_id(&self) -> &'static str {
        "cc.math.money_in_float"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "currency-shaped variable bound to a floating-point type"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Write) {
            if let Some(finding) = check_write(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

/// Check a single [`NodeKind::Write`] node. Returns a finding when the
/// target name is money-shaped AND the binding looks float-typed.
fn check_write(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let target = string_prop(ctx.batch, id, "target")?;
    if !is_money_name(target) {
        return None;
    }
    if !binding_looks_float(ctx, id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TimeMathFindingBlueprint {
        rule_id: "cc.math.money_in_float",
        category: Category::Bug,
        severity: Severity::Blocker,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{target}` looks like currency but is bound to a float"),
        explanation: format!(
            "Float-typed money loses cents. The decimal value 0.10 has no exact \
             IEEE-754 representation; summing many values silently drifts and \
             rounding rules (banker's vs round-half-up) become non-deterministic. \
             `{target}` matches the money-identifier table — store it as fixed-\
             point integer cents or a `Decimal` / `BigDecimal` instead."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace with one of: integer cents (`amount_cents: i64 = 1099`), \
             Python `decimal.Decimal('10.99')`, Rust `rust_decimal::Decimal`, \
             JS `BigInt` cents, or a domain `Money` newtype that wraps a \
             fixed-point integer."
                .into(),
        ),
        snippet: target.to_owned(),
        weight: 4,
    }))
}

/// Best-effort: does this binding look like it carries a float?
///
/// Two signals, in order:
///
/// 1. An explicit `type` / `type_name` / `binding_type` string property
///    naming a known floating type. (TODO(phase-4): wire when the
///    frontend emits binding types.)
/// 2. A float literal on the right-hand side of the same source line.
fn binding_looks_float(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    if explicit_type_is_float(ctx, id) {
        return true;
    }
    rhs_has_float_literal(ctx, id)
}

fn explicit_type_is_float(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    for key in ["type", "type_name", "binding_type", "annotation"] {
        if let Some(name) = string_prop(ctx.batch, id, key) {
            if is_float_type(name) {
                return true;
            }
        }
    }
    false
}

/// Look at the source line containing the Write node. Return true if it
/// contains a float literal (a decimal numeral with a `.`) anywhere
/// after the `=` operator.
fn rhs_has_float_literal(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let Some(range) = range_prop(ctx.batch, id, "range") else {
        return false;
    };
    let Some(path) = enclosing_file_path(ctx.batch, id) else {
        return false;
    };
    let bytes = ctx.source.get(path.as_path());
    let text = std::str::from_utf8(bytes).unwrap_or("");
    let line = nth_line(text, range.start.line);
    line.split_once('=')
        .is_some_and(|(_lhs, rhs)| contains_float_literal(rhs))
}

/// Extract the (1-based) `line_no` line from `text`, or empty.
fn nth_line(text: &str, line_no_1based: u32) -> &str {
    let want = line_no_1based.saturating_sub(1) as usize;
    text.lines().nth(want).unwrap_or("")
}
