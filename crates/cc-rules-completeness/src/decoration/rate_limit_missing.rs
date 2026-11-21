//! `cc.decoration.rate_limit_missing` — call to external API without
//! rate-limit primitive.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    body_contains_any, build_finding, enclosing_file_path, function_body_text, location_from_node,
    looks_like_external_dep_call, CompletenessFindingBlueprint,
};

/// Probe `cc.decoration.rate_limit_missing`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RateLimitMissingRule;

const LIMIT_NEEDLES: &[&str] = &[
    "ratelimit",
    "rate_limit",
    "RateLimit",
    "throttle",
    "Throttle",
    "Semaphore",
    "semaphore",
];

impl Rule for RateLimitMissingRule {
    fn rule_id(&self) -> &'static str {
        "cc.decoration.rate_limit_missing"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "external API call without rate limit"
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

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let callee = string_prop(ctx.batch, id, "name").unwrap_or("");
    if !looks_like_external_dep_call(callee) {
        return None;
    }
    let fn_id = enclosing_function(ctx, id)?;
    let body = function_body_text(ctx.batch, fn_id, ctx.source).unwrap_or_default();
    if body_contains_any(&body, LIMIT_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.decoration.rate_limit_missing",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.5),
        location,
        headline: format!("external call `{callee}` lacks a rate limiter"),
        explanation: "Calls to external APIs without rate limits eventually trip the \
             provider's quota. The provider then 429s the entire system, often during \
             unrelated traffic spikes."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the client with a rate-limit primitive (`tower::limit::RateLimit`, \
             `aiolimiter`, `golang.org/x/time/rate`)."
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
