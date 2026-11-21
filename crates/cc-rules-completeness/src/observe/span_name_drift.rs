//! `cc.observe.span_name_drift` — span name in
//! `instrument(name = "x")` differs from the function name.
//!
//! Heuristic: walk every `Decorator` whose name contains `instrument` /
//! `span` / `trace`. Read the decorator's `arg_name` property (frontend
//! lowers a `name = "..."` argument into this slot). If the decorated
//! function's `name` does not equal the arg_name, flag.

use cc_cpg::{EdgeKind, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{
    incoming_edges_of_kind, node_kind, nodes_of_kind, outgoing_edges_of_kind, string_prop,
};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, decorator_arg_name, enclosing_file_path, location_from_node,
    CompletenessFindingBlueprint,
};

/// Probe `cc.observe.span_name_drift`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SpanNameDriftRule;

impl Rule for SpanNameDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.observe.span_name_drift"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "instrument(name = ...) string drifted from the function name"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for dec in nodes_of_kind(ctx.batch, NodeKind::Decorator) {
            if let Some(f) = check_decorator(ctx, dec.id) {
                out.push(f);
            }
        }
        out
    }
}

fn check_decorator(ctx: &RuleContext<'_>, dec_id: NodeId) -> Option<Finding> {
    let dec_name = string_prop(ctx.batch, dec_id, "name")?;
    if !is_span_decorator(dec_name) {
        return None;
    }
    let declared = decorator_arg_name(ctx.batch, dec_id)?;
    let fn_id = decorated_fn(ctx, dec_id)?;
    let fn_name = string_prop(ctx.batch, fn_id, "name")?;
    if declared == fn_name {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, fn_id)?;
    let location = location_from_node(ctx.batch, dec_id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.observe.span_name_drift",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("span name `{declared}` does not match function `{fn_name}`"),
        explanation: "When a span name drifts from the function name, distributed \
             traces become misleading — searches by symbol fail to find the span."
            .into(),
        remediation: Remediation::SuggestedRewrite(format!(
            "Update the decorator to `name = \"{fn_name}\"`, or rename the function."
        )),
        snippet: format!("name=\"{declared}\" fn={fn_name}"),
        weight: 1,
    }))
}

fn is_span_decorator(name: &str) -> bool {
    name.contains("instrument") || name.contains("span") || name.contains("trace")
}

/// Resolve the function attached to this decorator.
///
/// Two CPG conventions are supported (per the helpers' decorator walker):
/// 1. Decorator's outgoing AST_PARENT to the function — phase-2 frontends.
/// 2. Decorator and function share the same parent and the decorator
///    precedes the function in source order.
fn decorated_fn(ctx: &RuleContext<'_>, dec_id: NodeId) -> Option<NodeId> {
    if let Some(target) = outgoing_edges_of_kind(ctx.batch, dec_id, EdgeKind::AST_PARENT)
        .map(|e| e.to)
        .find(|t| {
            matches!(
                node_kind(ctx.batch, *t),
                Some(NodeKind::Function | NodeKind::Method)
            )
        })
    {
        return Some(target);
    }
    let parent = outgoing_edges_of_kind(ctx.batch, dec_id, EdgeKind::AST_PARENT)
        .next()?
        .to;
    incoming_edges_of_kind(ctx.batch, parent, EdgeKind::AST_PARENT)
        .map(|e| e.from)
        .find(|c| {
            matches!(
                node_kind(ctx.batch, *c),
                Some(NodeKind::Function | NodeKind::Method)
            )
        })
}
