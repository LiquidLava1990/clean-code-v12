//! `cc.decoration.retry_no_backoff` — retry loop with constant interval
//! (`time.sleep(1)` in retry body, no exponential or jittered backoff).
//!
//! Heuristic: a function whose body contains `retry` AND `sleep(`/`thread::sleep`/`time.sleep`
//! but not `expon`/`backoff`/`jitter`.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    body_contains_any, build_finding, enclosing_file_path, function_body_text, is_top_level_fn,
    location_from_node, CompletenessFindingBlueprint,
};

/// Probe `cc.decoration.retry_no_backoff`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RetryNoBackoffRule;

const RETRY_NEEDLES: &[&str] = &["retry", "Retry", "RETRIES", "retries"];
const SLEEP_NEEDLES: &[&str] = &["sleep(", "thread::sleep", "time.sleep", "asyncio.sleep"];
const BACKOFF_NEEDLES: &[&str] = &["expon", "backoff", "jitter", "Jitter"];

impl Rule for RetryNoBackoffRule {
    fn rule_id(&self) -> &'static str {
        "cc.decoration.retry_no_backoff"
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
        "retry loop without exponential or jittered backoff"
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
    if !is_top_level_fn(ctx.batch, id) {
        return None;
    }
    let body = function_body_text(ctx.batch, id, ctx.source)?;
    if !body_contains_any(&body, RETRY_NEEDLES) {
        return None;
    }
    if !body_contains_any(&body, SLEEP_NEEDLES) {
        return None;
    }
    if body_contains_any(&body, BACKOFF_NEEDLES) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.decoration.retry_no_backoff",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{name}` retries with constant sleep — no backoff"),
        explanation: "Constant-interval retries collide on every recovery wave \
             (thundering herd) and waste capacity. Use exponential + jittered backoff."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace fixed `sleep(N)` with an exponential backoff helper \
             (`backoff::exponential` / `tenacity.retry(wait_exponential(jitter=1))`)."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}
