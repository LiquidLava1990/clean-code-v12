//! `cc.ops.missing_timeout` — network call without explicit timeout.
//!
//! Heuristic: enumerate every [`NodeKind::Call`] node, match the callee
//! against `HTTP_CLIENT_CALLEES`, then inspect the call's argument
//! text for any of `TIMEOUT_NEEDLES`. A miss flags the call.
//!
//! Family-25 ships a sibling `cc.decoration.timeout_missing` probe with
//! a broader callee table. Phase-4 simplification: emit independently;
//! the user tunes severity if they want one to defer to the other.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, call_args_text, callee_text, enclosing_file_path, location_from_node,
    matches_any, OpsFindingBlueprint, HTTP_CLIENT_CALLEES,
};

/// Family-12 probe `cc.ops.missing_timeout`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingTimeoutRule;

const TIMEOUT_NEEDLES: &[&str] = &[
    "timeout",
    "Timeout",
    "deadline",
    "Deadline",
    ".timeout(",
    "WithTimeout",
    "context.WithTimeout",
];

impl Rule for MissingTimeoutRule {
    fn rule_id(&self) -> &'static str {
        "cc.ops.missing_timeout"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Ops
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "network call without an explicit timeout"
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
    let callee = callee_text(ctx.batch, id);
    if !matches_any(&callee, HTTP_CLIENT_CALLEES) {
        return None;
    }
    let args = call_args_text(ctx.batch, id);
    if matches_any(&args, TIMEOUT_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(OpsFindingBlueprint {
        rule_id: "cc.ops.missing_timeout",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{}` has no timeout", short_callee(&callee)),
        explanation: "Network calls without timeouts hang indefinitely on partial \
             outages, holding threads / connections / goroutines until the kernel \
             reaps them. Always declare an explicit deadline."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Pass `timeout=Duration::from_secs(5)` / `timeout=5.0` / \
             `.timeout(Duration::from_secs(5))` / `context.WithTimeout(ctx, 5*time.Second)` \
             at the call site."
                .into(),
        ),
        snippet: callee.clone(),
        weight: 2,
    }))
}

fn short_callee(text: &str) -> &str {
    text.split_whitespace().next().unwrap_or(text)
}
