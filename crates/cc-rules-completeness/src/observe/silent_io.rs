//! `cc.observe.silent_io` — I/O call whose enclosing function has no
//! tracing/instrumentation marker AND whose body contains no `tracing::*`
//! invocation.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    body_contains_any, build_finding, enclosing_file_path, function_body_text,
    has_decorator_containing, location_from_node, looks_like_io_call, CompletenessFindingBlueprint,
};

/// Probe `cc.observe.silent_io`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SilentIoRule;

const TRACE_DECORATOR_NEEDLES: &[&str] =
    &["instrument", "trace_async", "meta_async", "traced", "span"];
const TRACING_INVOCATION_NEEDLES: &[&str] = &[
    "tracing::",
    "tracing.",
    "log.info",
    "log.debug",
    "log.warn",
    "log.error",
    "logger.",
    "span!",
    "info_span",
];

impl Rule for SilentIoRule {
    fn rule_id(&self) -> &'static str {
        "cc.observe.silent_io"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "I/O call inside an untraced function with no logging"
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
    if !looks_like_io_call(callee) {
        return None;
    }
    let fn_id = enclosing_function(ctx, call_id)?;
    if has_decorator_containing(ctx.batch, fn_id, TRACE_DECORATOR_NEEDLES) {
        return None;
    }
    let body = function_body_text(ctx.batch, fn_id, ctx.source).unwrap_or_default();
    if body_contains_any(&body, TRACING_INVOCATION_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, call_id)?;
    let location = location_from_node(ctx.batch, call_id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.observe.silent_io",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("silent I/O call `{callee}` — no tracing or log"),
        explanation: "I/O is the expensive boundary. A call to disk/network/db with \
             neither a span nor a log line means production failures lose all context."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the call in a span (`tracing::info_span!`) or emit a structured \
             log with the operation name + arguments + outcome."
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
