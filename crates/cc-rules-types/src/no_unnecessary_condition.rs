//! `cc.type.no_unnecessary_condition` — statically true / false
//! conditions and trivially redundant checks.
//!
//! Syntactic shadow of TypeScript ESLint's
//! `no-unnecessary-condition` and ESLint's `no-constant-condition`;
//! full version requires type-flow analysis. We detect:
//!
//! - Literal `if (true) { ... }` / `while (false) { ... }`
//! - Tautologies: `if (x !== undefined && x !== undefined)`
//! - Doubled identical operands: `if (x === x)` (already partly
//!   covered by `cc.bug.type_confusion`; we still emit our own
//!   finding so users see one rule per concept).
//!
//! Restricted to `ts` / `typescript` / `js` / `javascript`.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-UNNECESSARY-CONDITION.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoUnnecessaryConditionRule;

impl Rule for NoUnnecessaryConditionRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_unnecessary_condition"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "condition is statically constant or trivially redundant"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Branch, NodeKind::Loop] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_condition(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_condition(ctx: &RuleContext<'_>, node_id: NodeId) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, node_id)?;
    if !is_ts_or_js(&language) {
        return None;
    }
    let condition = string_prop(ctx.batch, node_id, "condition")?;
    let trigger = classify(condition)?;
    let path = enclosing_file_path(ctx.batch, node_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, node_id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_unnecessary_condition",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("redundant condition `{condition}` ({trigger})"),
        explanation: format!(
            "The condition `{condition}` is {trigger} — the branch is dead \
             code or the loop is unbounded / never-runs. Either remove the \
             unreachable branch, fix the predicate to reflect the actual \
             intent, or replace with the constant the condition collapses \
             to."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace the constant condition with the value it evaluates to, \
             or restructure the predicate so each clause adds new \
             information. If the constant is intentional (`while (true)` \
             event loop), spell it `// eslint-disable-next-line because <reason>`."
                .into(),
        ),
        snippet: condition.to_owned(),
        weight: 1,
    }))
}

fn is_ts_or_js(language: &str) -> bool {
    matches!(
        language.to_ascii_lowercase().as_str(),
        "ts" | "typescript" | "js" | "javascript"
    )
}

fn classify(condition: &str) -> Option<&'static str> {
    let trimmed = condition.trim();
    if matches!(trimmed, "true" | "1") {
        return Some("always true");
    }
    if matches!(trimmed, "false" | "0") {
        return Some("always false");
    }
    if let Some(parts) = split_logical_and(trimmed) {
        if parts.len() >= 2 && all_equal(&parts) {
            return Some("the same clause repeated");
        }
    }
    if let Some((lhs, rhs)) = split_eq(trimmed) {
        if lhs == rhs {
            return Some("comparing a value to itself");
        }
    }
    None
}

fn split_logical_and(text: &str) -> Option<Vec<&str>> {
    if !text.contains("&&") {
        return None;
    }
    Some(
        text.split("&&")
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect(),
    )
}

fn all_equal(parts: &[&str]) -> bool {
    parts.windows(2).all(|w| w[0] == w[1])
}

fn split_eq(text: &str) -> Option<(&str, &str)> {
    for sep in ["===", "!==", "==", "!="] {
        if let Some((lhs, rhs)) = text.split_once(sep) {
            return Some((lhs.trim(), rhs.trim()));
        }
    }
    None
}
