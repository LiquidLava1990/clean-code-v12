//! `cc.bug.float_money` — money-shaped variables stored in floats.
//!
//! Heuristic: every [`NodeKind::Variable`] / [`NodeKind::Parameter`] /
//! [`NodeKind::Write`] whose name looks like money
//! (`*_amount`, `*_price`, `*_cost`, `*_balance`, `*_total`, `currency_*`)
//! and whose annotated type / inferred type is a float type
//! (`float`, `f32`, `f64`, `number`) is reported.
//!
//! IEEE-754 floats cannot represent `0.10` exactly, so summing money in
//! floats accumulates rounding error. Use a fixed-point decimal type.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node, BugFindingBlueprint,
};

/// Family-3 probe R-FLOAT-MONEY.
#[derive(Debug, Default, Clone, Copy)]
pub struct FloatMoneyRule;

const MONEY_SUFFIXES: &[&str] = &["_amount", "_price", "_cost", "_balance", "_total", "_fee"];
const FLOAT_TYPES: &[&str] = &["float", "f32", "f64", "number", "Float", "Double", "double"];

impl Rule for FloatMoneyRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.float_money"
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
        "money-shaped variable bound to a float type"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Variable, NodeKind::Parameter, NodeKind::Write] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_node(ctx, node) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_node(ctx: &RuleContext<'_>, node: &Node) -> Option<Finding> {
    let name = node_name(ctx, node)?;
    if !looks_like_money(&name) {
        return None;
    }
    let ty = node_type(ctx, node)?;
    if !is_float_type(&ty) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, node.id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.float_money",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{name}: {ty}` stores money in a float"),
        explanation: format!(
            "`{name}` looks like a monetary value but is bound to `{ty}`. \
             IEEE-754 floats cannot represent decimal fractions exactly \
             (`0.10 + 0.20 != 0.30`), so summing money in floats produces \
             rounding errors that snowball through reports and reconciliation."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Use a fixed-point decimal type: Python `decimal.Decimal`, Rust \
             `rust_decimal::Decimal`, Go `shopspring/decimal`, JS `Big.js` / \
             `BigInt` minor units. Float types are reserved for measurements, \
             never money."
                .into(),
        ),
        snippet: format!("{name}: {ty}"),
        weight: 4,
    }))
}

fn node_name(ctx: &RuleContext<'_>, node: &Node) -> Option<String> {
    for key in ["name", "target"] {
        if let Some(v) = string_prop(ctx.batch, node.id, key) {
            return Some(v.to_owned());
        }
    }
    None
}

fn node_type(ctx: &RuleContext<'_>, node: &Node) -> Option<String> {
    for key in ["type", "annotated_type", "inferred_type", "target_type"] {
        if let Some(v) = string_prop(ctx.batch, node.id, key) {
            return Some(v.to_owned());
        }
    }
    None
}

fn looks_like_money(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("currency_") {
        return true;
    }
    MONEY_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

fn is_float_type(ty: &str) -> bool {
    let trimmed = ty.trim();
    FLOAT_TYPES.iter().any(|t| trimmed == *t)
}

/// Diagnostic helper to keep [`NodeId`] in scope without pulling
/// `cc_frontend::query::node_by_id` directly in tests.
#[must_use]
#[allow(dead_code)]
pub(crate) fn diag_id(node: &Node) -> NodeId {
    node.id
}
