//! `cc.decoration.timeout_missing` — network/DB call without an
//! explicit timeout argument.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, looks_like_external_dep_call,
    looks_like_io_call, CompletenessFindingBlueprint,
};

/// Probe `cc.decoration.timeout_missing`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TimeoutMissingRule;

const TIMEOUT_NEEDLES: &[&str] = &["timeout", "Timeout", "deadline", "Deadline"];

impl Rule for TimeoutMissingRule {
    fn rule_id(&self) -> &'static str {
        "cc.decoration.timeout_missing"
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
        "network/DB/IPC call with no explicit timeout"
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
    if !looks_like_io_call(callee) && !looks_like_external_dep_call(callee) {
        return None;
    }
    let args = string_prop(ctx.batch, id, "args").unwrap_or("");
    if TIMEOUT_NEEDLES.iter().any(|n| args.contains(n)) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.decoration.timeout_missing",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("`{callee}` has no timeout"),
        explanation: "Network and DB calls without timeouts hang on partial outages, \
             holding threads/connections until the kernel kills them. Always declare \
             an explicit deadline."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Pass `timeout=Duration::from_secs(5)` / `timeout=5.0` / `WithTimeout(5s)` \
             at the call site."
                .into(),
        ),
        snippet: callee.to_owned(),
        weight: 1,
    }))
}
