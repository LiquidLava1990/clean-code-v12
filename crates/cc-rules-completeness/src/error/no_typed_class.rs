//! `cc.error.no_typed_class` — `raise Exception(...)` / `panic!(...)` /
//! `throw new Error(...)` without a project-specific typed class.
//!
//! Severity: BLOCKER. These patterns are real bugs — callers cannot
//! pattern-match on the exception type to recover.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.error.no_typed_class`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoTypedClassRule;

impl Rule for NoTypedClassRule {
    fn rule_id(&self) -> &'static str {
        "cc.error.no_typed_class"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "raise/throw/panic with a generic error class"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Call, NodeKind::Return] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(f) = check_call(ctx, node.id) {
                    out.push(f);
                }
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let callee = string_prop(ctx.batch, id, "name").unwrap_or("");
    let exc_type = string_prop(ctx.batch, id, "exception_type").unwrap_or("");
    if !is_generic_raise(callee, exc_type) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.error.no_typed_class",
        category: Category::Bug,
        severity: Severity::Blocker,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "`{}` raises a generic error type",
            if !exc_type.is_empty() {
                exc_type
            } else {
                callee
            }
        ),
        explanation: "Generic Exception/Error/panic loses type information at the \
             catch site. Define a domain-specific subclass (e.g. `class \
             ConfigInvalidError(Error):`) so callers can pattern-match."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace with a typed error class that carries an `ErrCode` field.".into(),
        ),
        snippet: format!("{callee} {exc_type}"),
        weight: 2,
    }))
}

fn is_generic_raise(callee: &str, exc_type: &str) -> bool {
    matches!(
        exc_type,
        "Exception" | "BaseException" | "Error" | "RuntimeError" | "ValueError"
    ) || matches!(callee, "panic!" | "panic")
        || (callee == "throw" && exc_type.starts_with("Error"))
}
