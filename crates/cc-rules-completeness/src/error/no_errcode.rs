//! `cc.error.no_errcode` — typed-error class without an associated
//! error-code string field (`ErrCode` discipline).
//!
//! Heuristic: a `Class` whose `name` ends in `Error` / `Exception` and
//! whose body text doesn't mention `errcode` / `ErrCode` / `code = ` /
//! `code: `.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, function_body_text, location_from_node,
    CompletenessFindingBlueprint,
};

/// Probe `cc.error.no_errcode`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoErrcodeRule;

const ERRCODE_NEEDLES: &[&str] = &[
    "errcode", "ErrCode", "err_code", "ERR_CODE", "code: ", "code = ",
];

impl Rule for NoErrcodeRule {
    fn rule_id(&self) -> &'static str {
        "cc.error.no_errcode"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "typed error class lacks a stable ErrCode field"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for class in nodes_of_kind(ctx.batch, NodeKind::Class) {
            if let Some(f) = check_class(ctx, class.id) {
                out.push(f);
            }
        }
        out
    }
}

fn check_class(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    if !is_error_class(name) {
        return None;
    }
    let body = function_body_text(ctx.batch, id, ctx.source).unwrap_or_default();
    if ERRCODE_NEEDLES.iter().any(|n| body.contains(n)) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.error.no_errcode",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{name}` has no stable ErrCode field"),
        explanation: "Without a stable `errcode` string, error sites can't be grouped \
             across releases. Each error class needs a unique, never-changing code so \
             dashboards and runbooks survive refactors."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add `errcode: str = \"E1234_DESCRIPTIVE_TAG\"` (Python) or \
             `const ERRCODE: &str = \"...\"` (Rust)."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}

fn is_error_class(name: &str) -> bool {
    name.ends_with("Error") || name.ends_with("Exception")
}
