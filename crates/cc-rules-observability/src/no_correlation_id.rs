//! `cc.obs.no_correlation_id` — outbound HTTP / RPC call with no
//! surrounding tracing context.
//!
//! Heuristic (Phase-4 simplification): every [`NodeKind::Call`] whose
//! callee text matches an outbound HTTP / RPC primitive
//! (`crate::helpers::HTTP_CALLEES`) is checked against the enclosing
//! function. If no descendant of that function calls a tracing /
//! span / instrument primitive, fire.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_matches, callee_text, enclosing_file_path, enclosing_function,
    is_test_file_path, location_from_node, looks_like_rule_pack_source, ObsFindingBlueprint,
    HTTP_CALLEES, TRACING_CALLEES,
};

/// Family-11 probe R-OBS-NO-CORRELATION-ID.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCorrelationIdRule;

const TRACEPARENT_HEADER_HINTS: &[&str] = &[
    "traceparent",
    "tracestate",
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "b3-traceid",
];

impl Rule for NoCorrelationIdRule {
    fn rule_id(&self) -> &'static str {
        "cc.obs.no_correlation_id"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.65)
    }
    fn description(&self) -> &'static str {
        "outbound HTTP call lacks a surrounding tracing span / correlation header"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let text = callee_text(ctx.batch, id);
    if !callee_matches(&text, HTTP_CALLEES) {
        return None;
    }
    if call_has_correlation_header(ctx, id) {
        return None;
    }
    let fn_id = enclosing_function(ctx.batch, id)?;
    if function_has_tracing(ctx, fn_id) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(emit(location, &text))
}

fn call_has_correlation_header(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let args = string_prop(ctx.batch, id, "args").unwrap_or("");
    let lower = args.to_ascii_lowercase();
    TRACEPARENT_HEADER_HINTS.iter().any(|h| lower.contains(h))
}

fn function_has_tracing(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    let mut frontier = vec![fn_id];
    let mut visited: u32 = 0;
    while let Some(cur) = frontier.pop() {
        visited = visited.saturating_add(1);
        if visited > 4096 {
            return false;
        }
        for child in ast_children(ctx.batch, cur) {
            if call_is_tracing(ctx, child) {
                return true;
            }
            frontier.push(child);
        }
    }
    false
}

fn call_is_tracing(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    if node_kind(ctx.batch, id) != Some(NodeKind::Call) {
        return false;
    }
    let text = callee_text(ctx.batch, id);
    callee_matches(&text, TRACING_CALLEES)
}

fn emit(location: cc_finding::Location, callee: &str) -> Finding {
    let snippet: String = callee.chars().take(120).collect();
    build_finding(ObsFindingBlueprint {
        rule_id: "cc.obs.no_correlation_id",
        severity: Severity::Required,
        confidence: Confidence::new(0.65),
        location,
        headline: "outbound HTTP call lacks correlation context".into(),
        explanation: "The enclosing function makes an outbound HTTP / RPC \
             call but emits no `tracing::*` / `span!` / `instrument` / \
             `with_context` macro and the call passes no `traceparent` / \
             `x-request-id` header. Distributed traces will break at this \
             hop — every downstream span is rooted at a fresh trace id, \
             so causality is lost."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the function in `#[tracing::instrument]` (Rust) / \
             `@tracer.start_as_current_span` (Python) / \
             `tracer.startActiveSpan` (TS) / `otel.Tracer.Start` (Go), or \
             explicitly inject `traceparent` into the outbound headers."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
