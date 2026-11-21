//! `cc.ops.no_circuit_breaker` — external dep call without circuit breaker.
//!
//! Heuristic: enumerate every [`NodeKind::Function`] / [`NodeKind::Method`]
//! whose name suggests an external client (`*_client*`, `fetch_*`,
//! `call_*`). For each, walk its descendant `Call` nodes; if any call
//! resolves to an HTTP / DB / RPC client and no call resolves to a
//! known circuit-breaker library, flag the function.
//!
//! Phase-4 simplification: only the function's direct AST children are
//! inspected (matches `retry_no_backoff` traversal depth). Frontends
//! that flatten the AST surface every body call as a direct child;
//! deeply nested helpers are caught by their enclosing function.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, location_from_node, matches_any,
    OpsFindingBlueprint, BREAKER_LIB_CALLEES, DB_CLIENT_CALLEES, HTTP_CLIENT_CALLEES,
};

/// Family-12 probe `cc.ops.no_circuit_breaker`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCircuitBreakerRule;

impl Rule for NoCircuitBreakerRule {
    fn rule_id(&self) -> &'static str {
        "cc.ops.no_circuit_breaker"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Ops
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.55)
    }
    fn description(&self) -> &'static str {
        "external dependency call without a circuit breaker"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Function) {
            if let Some(f) = check_function(ctx, node.id) {
                out.push(f);
            }
        }
        for node in nodes_of_kind(ctx.batch, NodeKind::Method) {
            if let Some(f) = check_function(ctx, node.id) {
                out.push(f);
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, fn_id: NodeId) -> Option<Finding> {
    let name = string_prop(ctx.batch, fn_id, "name").unwrap_or("");
    if !looks_like_client_function(name) {
        return None;
    }
    let calls = collect_body_calls(ctx, fn_id);
    if !any_external_call(ctx, &calls) {
        return None;
    }
    if any_breaker_call(ctx, &calls) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, fn_id)?;
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(OpsFindingBlueprint {
        rule_id: "cc.ops.no_circuit_breaker",
        severity: Severity::Required,
        confidence: Confidence::new(0.55),
        location,
        headline: format!("`{name}` calls an external dependency without a circuit breaker"),
        explanation: "Without a circuit breaker, every caller waits the full \
             timeout for every failing request. The dependency stays \
             saturated, the caller's pool fills, and a partial outage \
             becomes a full outage."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the call in a circuit breaker — `failsafe`, \
             `tower::ServiceBuilder::circuit_breaker`, `pybreaker`, \
             `polly`, or `resilience4j`. Configure failure thresholds, \
             half-open recovery, and a fallback."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 3,
    }))
}

fn looks_like_client_function(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("_client")
        || lower.ends_with("client")
        || lower.starts_with("fetch_")
        || lower.starts_with("call_")
        || lower.starts_with("get_remote")
        || lower.starts_with("post_remote")
}

fn collect_body_calls(ctx: &RuleContext<'_>, fn_id: NodeId) -> Vec<NodeId> {
    ast_children(ctx.batch, fn_id)
        .filter(|id| node_kind(ctx.batch, *id) == Some(NodeKind::Call))
        .collect()
}

fn any_external_call(ctx: &RuleContext<'_>, calls: &[NodeId]) -> bool {
    calls.iter().any(|id| {
        let text = callee_text(ctx.batch, *id);
        matches_any(&text, HTTP_CLIENT_CALLEES) || matches_any(&text, DB_CLIENT_CALLEES)
    })
}

fn any_breaker_call(ctx: &RuleContext<'_>, calls: &[NodeId]) -> bool {
    calls.iter().any(|id| {
        let text = callee_text(ctx.batch, *id);
        matches_any(&text, BREAKER_LIB_CALLEES)
    })
}
