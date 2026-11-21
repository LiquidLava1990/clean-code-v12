//! `cc.contract.event_unsigned` — `bus.emit(...)` / `EventBus::publish`
//! call without surrounding signature attachment (`signed=True`,
//! `sign_with`, `Signed<>` wrapper).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    body_contains_any, build_finding, enclosing_file_path, function_body_text, is_emit_callee,
    location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.contract.event_unsigned`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EventUnsignedRule;

const SIGN_NEEDLES: &[&str] = &[
    "signed=True",
    "signed: true",
    "sign_with",
    "Signed<",
    "Signed::",
    ".sign(",
];

impl Rule for EventUnsignedRule {
    fn rule_id(&self) -> &'static str {
        "cc.contract.event_unsigned"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "event emit without signature attachment"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for call in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(f) = check_call(ctx, call.id) {
                out.push(f);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, call_id: NodeId) -> Option<Finding> {
    let callee = string_prop(ctx.batch, call_id, "name").unwrap_or("");
    if !is_emit_callee(callee) {
        return None;
    }
    let fn_id = enclosing_function(ctx, call_id)?;
    let body = function_body_text(ctx.batch, fn_id, ctx.source).unwrap_or_default();
    if body_contains_any(&body, SIGN_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, call_id)?;
    let location = location_from_node(ctx.batch, call_id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.contract.event_unsigned",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("event emit `{callee}` is not signed"),
        explanation: "Unsigned events let producers and consumers drift across releases. \
             Sign the event so consumers can verify origin and reject replays."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the payload in a signature primitive (`Signed<>` / `sign_with` / \
             `signed=True`) before emit."
                .into(),
        ),
        snippet: callee.to_owned(),
        weight: 1,
    }))
}

fn enclosing_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<NodeId> {
    let mut cur = id;
    for _ in 0..256_u16 {
        cur = ast_parent(ctx.batch, cur)?;
        if matches!(
            node_kind(ctx.batch, cur),
            Some(NodeKind::Function | NodeKind::Method)
        ) {
            return Some(cur);
        }
    }
    None
}
