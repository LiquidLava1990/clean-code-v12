//! `cc.decoration.circuit_breaker_missing` — call to an external
//! dependency without circuit-breaker library wrap.
//!
//! Heuristic: a `Call` whose name matches an external-dep pattern AND
//! whose enclosing function body contains no circuit-breaker library
//! reference (`circuit`, `breaker`, `pyfailsafe`, `tenacity.circuit`,
//! `gobreaker`).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    body_contains_any, build_finding, enclosing_file_path, function_body_text, location_from_node,
    looks_like_external_dep_call, CompletenessFindingBlueprint,
};

/// Probe `cc.decoration.circuit_breaker_missing`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CircuitBreakerMissingRule;

const BREAKER_NEEDLES: &[&str] = &[
    "circuit",
    "breaker",
    "Breaker",
    "pyfailsafe",
    "gobreaker",
    "Hystrix",
];

impl Rule for CircuitBreakerMissingRule {
    fn rule_id(&self) -> &'static str {
        "cc.decoration.circuit_breaker_missing"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "external dependency call without circuit breaker"
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
    if body_contains_any(&body, BREAKER_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.decoration.circuit_breaker_missing",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("external call `{callee}` lacks a circuit breaker"),
        explanation: "External dependencies fail in waves — without a circuit breaker, \
             every retry contributes to the upstream brownout. Wrap the call so the \
             system fails fast under sustained errors."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the call with `gobreaker` (Go) / `pyfailsafe` (Python) / \
             `tower::limit::ConcurrencyLimit + retry` (Rust)."
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
