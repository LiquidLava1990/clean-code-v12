//! `cc.ops.no_rate_limit` — external API call without throttle.
//!
//! Heuristic: enumerate every [`NodeKind::Function`] / [`NodeKind::Method`]
//! that contains an HTTP / DB client call but no rate-limit-library
//! call. Severity Nit — many legitimate paths skip rate limiting
//! (one-shot CLI, throwaway script). The rule exists to surface the
//! axis, not to gate merges.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, location_from_node, matches_any,
    OpsFindingBlueprint, DB_CLIENT_CALLEES, HTTP_CLIENT_CALLEES, RATE_LIMIT_LIB_CALLEES,
};

/// Family-12 probe `cc.ops.no_rate_limit`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRateLimitRule;

impl Rule for NoRateLimitRule {
    fn rule_id(&self) -> &'static str {
        "cc.ops.no_rate_limit"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Ops
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "external API call without an explicit rate limiter"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, fn_id: NodeId) -> Option<Finding> {
    let calls = body_calls(ctx, fn_id);
    if !any_external_call(ctx, &calls) {
        return None;
    }
    if any_rate_limit_call(ctx, &calls) {
        return None;
    }
    let name = string_prop(ctx.batch, fn_id, "name").unwrap_or("<anonymous>");
    let path = enclosing_file_path(ctx.batch, fn_id)?;
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(OpsFindingBlueprint {
        rule_id: "cc.ops.no_rate_limit",
        severity: Severity::Nit,
        confidence: Confidence::new(0.5),
        location,
        headline: format!("`{name}` calls an external API with no rate limiter"),
        explanation: "Calls in tight loops to third-party APIs without a \
             rate limiter risk hitting upstream quotas, 429 storms, and \
             temporary IP blocks. A throttle keeps the caller polite and \
             predictable under load."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the call in a rate limiter — `governor::RateLimiter`, \
             `tower::limit::RateLimitLayer`, `bottleneck`, or a token-bucket \
             helper. Configure per-endpoint quotas where possible."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}

fn body_calls(ctx: &RuleContext<'_>, fn_id: NodeId) -> Vec<NodeId> {
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

fn any_rate_limit_call(ctx: &RuleContext<'_>, calls: &[NodeId]) -> bool {
    calls.iter().any(|id| {
        let text = callee_text(ctx.batch, *id);
        matches_any(&text, RATE_LIMIT_LIB_CALLEES)
    })
}
