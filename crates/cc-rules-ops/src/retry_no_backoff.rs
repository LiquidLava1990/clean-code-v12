//! `cc.ops.retry_no_backoff` — retry loop with constant interval.
//!
//! Heuristic: walk every [`NodeKind::Loop`]; inspect its descendant
//! `Call` nodes for sleep callees ([`SLEEP_CALLEES`]). If the sleep
//! argument text resolves to a numeric literal (matches
//! [`is_numeric_literal_arg`]) and no retry-library callee
//! ([`RETRY_LIB_CALLEES`]) appears in the loop body, flag the loop as
//! missing exponential / jittered backoff.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, nodes_of_kind};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, call_args_text, callee_text, enclosing_file_path, location_from_node,
    matches_any, OpsFindingBlueprint, RETRY_LIB_CALLEES,
};

/// Sleep / blocking-delay callees that drive a retry loop's inter-attempt
/// interval. A constant numeric argument paired with one of these is the
/// classic "no backoff" smell.
const SLEEP_CALLEES: &[&str] = &[
    "time.sleep",
    "asyncio.sleep",
    "tokio::time::sleep",
    "thread::sleep",
    "std::thread::sleep",
    "time.Sleep",
    "setTimeout",
];

/// Family-12 probe `cc.ops.retry_no_backoff`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RetryNoBackoffRule;

impl Rule for RetryNoBackoffRule {
    fn rule_id(&self) -> &'static str {
        "cc.ops.retry_no_backoff"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Ops
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "retry loop sleeps for a constant interval — no exponential / jittered backoff"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Loop) {
            if let Some(finding) = check_loop(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_loop(ctx: &RuleContext<'_>, loop_id: NodeId) -> Option<Finding> {
    let calls = collect_descendant_calls(ctx, loop_id);
    if uses_retry_library(ctx, &calls) {
        return None;
    }
    let constant_sleep = first_constant_sleep(ctx, &calls)?;
    let path = enclosing_file_path(ctx.batch, loop_id)?;
    let location = location_from_node(ctx.batch, loop_id, path);
    Some(build_finding(OpsFindingBlueprint {
        rule_id: "cc.ops.retry_no_backoff",
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: "retry loop sleeps for a constant interval".into(),
        explanation: "Constant-interval retry loops hammer a struggling \
             dependency at a fixed cadence. Under load this synchronises \
             every caller's retry storm and amplifies the outage instead \
             of giving the dependency room to recover."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Use exponential backoff with jitter — `tenacity.retry`, \
             `backoff`, `tokio_retry::ExponentialBackoff`, or hand-rolled \
             `delay = base * 2^attempt + random_jitter`. Cap the maximum \
             delay and the total attempt count."
                .into(),
        ),
        snippet: callee_text(ctx.batch, constant_sleep),
        weight: 2,
    }))
}

fn collect_descendant_calls(ctx: &RuleContext<'_>, loop_id: NodeId) -> Vec<NodeId> {
    // Phase-4 simplification: AST_PARENT in this CPG points child→parent,
    // so direct children come from `ast_children`. We collect direct
    // children only — a deep walk would amplify false positives across
    // unrelated nested loops.
    ast_children(ctx.batch, loop_id)
        .filter(|id| cc_frontend::query::node_kind(ctx.batch, *id) == Some(NodeKind::Call))
        .collect()
}

fn uses_retry_library(ctx: &RuleContext<'_>, calls: &[NodeId]) -> bool {
    calls.iter().any(|id| {
        let text = callee_text(ctx.batch, *id);
        matches_any(&text, RETRY_LIB_CALLEES)
    })
}

fn first_constant_sleep(ctx: &RuleContext<'_>, calls: &[NodeId]) -> Option<NodeId> {
    calls.iter().copied().find(|id| {
        let callee = callee_text(ctx.batch, *id);
        if !matches_any(&callee, SLEEP_CALLEES) {
            return false;
        }
        let args = call_args_text(ctx.batch, *id);
        is_numeric_literal_arg(&args)
    })
}

/// True iff `args` looks like a single numeric literal (integer or
/// float) — the "constant interval" signal. An expression involving
/// variables, multiplication, or attribute access fails the match.
fn is_numeric_literal_arg(args: &str) -> bool {
    let trimmed = args.trim().trim_end_matches(',').trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == '_')
        && trimmed.chars().any(|c| c.is_ascii_digit())
}
