//! `cc.deploy.missing_feature_flag` — risky-name function whose body
//! contains no feature-flag evaluation.
//!
//! Heuristic: walk every [`NodeKind::Function`] / [`NodeKind::Method`]
//! whose `name` starts with one of the
//! `crate::helpers::RISKY_NAME_PREFIXES` markers (`experimental_`,
//! `beta_`, `new_`, `v2_`). For each, descend the AST and look for any
//! [`NodeKind::Call`] whose callee text contains a flag-library marker
//! (`crate::helpers::FLAG_LIBRARY_CALLEES`). Functions that
//! self-classify as risky but evaluate no flag are flagged at
//! `Severity::Nit` so adoption is gradual.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, DeployFindingBlueprint, FLAG_LIBRARY_CALLEES, RISKY_NAME_PREFIXES,
};

/// Family-13 probe R-DEPLOY-MISSING-FLAG.
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingFeatureFlagRule;

impl Rule for MissingFeatureFlagRule {
    fn rule_id(&self) -> &'static str {
        "cc.deploy.missing_feature_flag"
    }
    fn category(&self) -> Category {
        Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.55)
    }
    fn description(&self) -> &'static str {
        "experimental_/beta_/new_/v2_ function does not evaluate a feature flag"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_fn(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_fn(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    let prefix = matched_risky_prefix(name)?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if fn_body_evaluates_flag(ctx, id) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(DeployFindingBlueprint {
        rule_id: "cc.deploy.missing_feature_flag",
        severity: Severity::Nit,
        confidence: Confidence::new(0.55),
        location,
        headline: format!("`{name}` is named `{prefix}*` but evaluates no feature flag"),
        explanation: format!(
            "The name `{name}` self-classifies as risky (prefix `{prefix}`), \
             yet the body never calls a flag-library evaluator \
             (`feature_flag` / `is_enabled` / `flag.evaluate` / \
             `LaunchDarkly` / `Unleash` / `GrowthBook`). Risky paths that \
             ship without a kill-switch leave you with `git revert` as the \
             only rollback — minutes of outage instead of seconds."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the entry point with `if not flags.is_enabled('experimental_x', \
             user): return legacy(...)`. The flag must default to OFF in \
             production config; flip it on for an internal cohort first, \
             watch metrics, then ramp."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    }))
}

fn matched_risky_prefix(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    RISKY_NAME_PREFIXES
        .iter()
        .copied()
        .find(|p| lower.starts_with(p))
}

fn fn_body_evaluates_flag(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    let mut stack = vec![fn_id];
    let mut budget: u16 = 4096;
    while let Some(cur) = stack.pop() {
        if budget == 0 {
            return false;
        }
        budget -= 1;
        for child in ast_children(ctx.batch, cur) {
            if call_evaluates_flag(ctx, child) {
                return true;
            }
            push_unless_nested_fn(ctx, child, &mut stack);
        }
    }
    false
}

fn call_evaluates_flag(ctx: &RuleContext<'_>, child: NodeId) -> bool {
    if node_kind(ctx.batch, child) != Some(NodeKind::Call) {
        return false;
    }
    let text = callee_text(ctx.batch, child);
    FLAG_LIBRARY_CALLEES.iter().any(|n| text.contains(*n))
}

fn push_unless_nested_fn(ctx: &RuleContext<'_>, child: NodeId, stack: &mut Vec<NodeId>) {
    if matches!(
        node_kind(ctx.batch, child),
        Some(NodeKind::Function | NodeKind::Method)
    ) {
        return;
    }
    stack.push(child);
}
