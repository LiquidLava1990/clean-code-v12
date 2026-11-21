//! `cc.type.switch_exhaustiveness` — `switch` over a union / enum
//! identifier without a `default:` clause.
//!
//! Syntactic shadow of TypeScript's exhaustive-switch and Go
//! golangci-lint's `exhaustive`; full version requires type-flow
//! analysis to enumerate the union variants. We approximate via a
//! purely syntactic check: the [`NodeKind::Branch`] node carries a
//! `kind == "switch"` property, the `discriminant` property is a bare
//! identifier, the `cases` property lists at least two `case '<lit>':`
//! arms, and `has_default` is `false` (or missing).
//!
//! Restricted to `ts` / `typescript` / `go`.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{bool_prop, int_prop, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-SWITCH-EXHAUSTIVENESS.
#[derive(Debug, Default, Clone, Copy)]
pub struct SwitchExhaustivenessRule;

impl Rule for SwitchExhaustivenessRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.switch_exhaustiveness"
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
        "switch over an identifier without a default clause and at least two literal cases"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Branch) {
            if let Some(finding) = check_switch(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_switch(ctx: &RuleContext<'_>, branch_id: NodeId) -> Option<Finding> {
    let (discriminant, case_count) = qualify_switch(ctx, branch_id)?;
    let path = enclosing_file_path(ctx.batch, branch_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, branch_id, path);
    Some(emit_finding(location, discriminant, case_count))
}

fn qualify_switch<'b>(ctx: &RuleContext<'b>, branch_id: NodeId) -> Option<(&'b str, i64)> {
    if string_prop(ctx.batch, branch_id, "kind").unwrap_or("") != "switch" {
        return None;
    }
    let language = enclosing_file_language(ctx.batch, branch_id)?;
    if !is_supported(&language) {
        return None;
    }
    if has_default(ctx, branch_id) {
        return None;
    }
    let count = case_count(ctx, branch_id);
    if count < 2 {
        return None;
    }
    let discriminant = string_prop(ctx.batch, branch_id, "discriminant").unwrap_or("");
    if !is_bare_identifier(discriminant) {
        return None;
    }
    Some((discriminant, count))
}

fn emit_finding(location: cc_finding::Location, discriminant: &str, case_count: i64) -> Finding {
    build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.switch_exhaustiveness",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "switch on `{discriminant}` lacks `default:` ({case_count} literal cases)"
        ),
        explanation: format!(
            "Switching on `{discriminant}` with {case_count} literal cases \
             but no `default:` clause silently no-ops every unhandled \
             variant. When the union grows a new member, every existing \
             switch becomes wrong and the compiler will not warn."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add an exhaustive `default:` clause. In TypeScript, assert \
             `const _exhaustive: never = value;` so the compiler errors when \
             a new variant lands. In Go, return an `error` describing the \
             unexpected value instead of silently falling through."
                .into(),
        ),
        snippet: discriminant.to_owned(),
        weight: 2,
    })
}

fn is_supported(language: &str) -> bool {
    matches!(
        language.to_ascii_lowercase().as_str(),
        "ts" | "typescript" | "go"
    )
}

fn has_default(ctx: &RuleContext<'_>, branch_id: NodeId) -> bool {
    if bool_prop(ctx.batch, branch_id, "has_default").unwrap_or(false) {
        return true;
    }
    let cases = string_prop(ctx.batch, branch_id, "cases").unwrap_or("");
    cases.contains("default:") || cases.contains("default ")
}

fn case_count(ctx: &RuleContext<'_>, branch_id: NodeId) -> i64 {
    if let Some(n) = int_prop(ctx.batch, branch_id, "case_count") {
        return n;
    }
    let cases = string_prop(ctx.batch, branch_id, "cases").unwrap_or("");
    cases.matches("case ").count() as i64
}

fn is_bare_identifier(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && trimmed
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}
