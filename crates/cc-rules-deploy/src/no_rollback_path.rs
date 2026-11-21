//! `cc.deploy.no_rollback_path` — destructive filesystem call without
//! a rollback / dry-run guard.
//!
//! Phase-4 simplification: every [`NodeKind::Call`] whose callee text
//! matches one of the destructive APIs in
//! [`crate::helpers::DESTRUCTIVE_CALLEES`] is flagged at
//! `Severity::Required`. Test files and rule-pack source (which embeds
//! the needle list) are skipped.
//!
//! TODO(phase-5): narrow with a "no dry-run / feature-flag guard in the
//! enclosing function" check once flow-sensitive analysis lands.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, DeployFindingBlueprint, DESTRUCTIVE_CALLEES,
};

/// Family-13 probe R-DEPLOY-NO-ROLLBACK.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRollbackPathRule;

impl Rule for NoRollbackPathRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.no_rollback_path"
    }
    fn category(&self) -> Category {
        Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "destructive filesystem call without a rollback / dry-run guard"
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
    let text = callee_text(ctx.batch, id);
    let needle = DESTRUCTIVE_CALLEES.iter().find(|n| text.contains(*n))?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(DeployFindingBlueprint {
        rule_id: "cc.deploy.no_rollback_path",
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("`{needle}` is irreversible — wrap with a dry-run / rollback guard"),
        explanation: format!(
            "`{needle}` deletes data with no built-in undo. Production deploys \
             that hit this call without a `dry_run` parameter, feature-flag \
             gate, or two-step (mark-then-sweep) protocol can lose customer \
             data on a single bad rollout — and rollback is impossible after \
             the call returns."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add a `dry_run: bool` parameter that short-circuits the destructive \
             branch, gate the call behind a feature flag (LaunchDarkly / Unleash \
             / GrowthBook), or split into two phases: mark for deletion, sweep \
             after a soak window. Log every targeted path before deleting."
                .into(),
        ),
        snippet: text,
        weight: 4,
    }))
}
