//! `cc.observe.missing_correlation_id` — RPC entry point that does not
//! propagate trace context to outbound calls.
//!
//! Heuristic (Phase 2): a function whose name looks like an RPC entry
//! (`handle_*`, `*_endpoint`, `*_handler`) whose body contains an
//! outbound call (`fetch`, `requests.`, `reqwest::`, `client.`) but does
//! not reference the correlation/trace context (`traceparent`,
//! `Context::current`, `correlation_id`, `trace_id`).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    body_contains_any, build_finding, enclosing_file_path, function_body_text, is_rpc_entry_name,
    location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.observe.missing_correlation_id`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingCorrelationIdRule;

const OUTBOUND_NEEDLES: &[&str] = &[
    "fetch(",
    "requests.",
    "reqwest::",
    "client.",
    "Client::",
    "http.get",
    "http.post",
];
const CORRELATION_NEEDLES: &[&str] = &[
    "traceparent",
    "Context::current",
    "Context.current",
    "correlation_id",
    "trace_id",
    "x-request-id",
    "X-Request-Id",
];

impl Rule for MissingCorrelationIdRule {
    fn rule_id(&self) -> &'static str {
        "cc.observe.missing_correlation_id"
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
        "RPC entry point makes outbound calls without forwarding trace context"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(f) = check_fn(ctx, node.id) {
                    out.push(f);
                }
            }
        }
        out
    }
}

fn check_fn(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    if !is_rpc_entry_name(name) {
        return None;
    }
    let body = function_body_text(ctx.batch, id, ctx.source)?;
    if !body_contains_any(&body, OUTBOUND_NEEDLES) {
        return None;
    }
    if body_contains_any(&body, CORRELATION_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.observe.missing_correlation_id",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("RPC entry `{name}` does not propagate trace context"),
        explanation: "Outbound calls from an RPC handler must forward the current \
             trace/correlation id so distributed traces stitch end-to-end. Without it, \
             every outbound hop appears as a fresh root."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Forward `traceparent` / `Context::current()` / `correlation_id` from the \
             incoming request into outbound headers."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}
