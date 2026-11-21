//! `cc.slop.unused_helper` — flag a helper-named function (per
//! `cc.slop.fake_thoughtful_name`'s suffix pattern) that has zero
//! incoming `CG_CALLS` / `REFERENCES` edges in the same file.
//!
//! Skips silently when the lifted batch has no call-graph or reference
//! edges (the frontend has not done resolution, so every helper would
//! look unused). Mirrors the gating pattern used by `cc.shape.dead_code`.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{incoming_edges_of_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_fake_thoughtful_suffix, location_from_node,
    SlopFindingBlueprint,
};

/// Family-1 rule R-SLOP-UNUSED-HELPER.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnusedHelperRule;

impl Rule for UnusedHelperRule {
    fn rule_id(&self) -> &'static str {
        "cc.slop.unused_helper"
    }
    fn category(&self) -> Category {
        Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "helper-named function has no incoming references"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        if !batch_has_call_resolution(ctx.batch) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_symbol(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn batch_has_call_resolution(batch: &CpgWriteBatch) -> bool {
    batch
        .edges()
        .iter()
        .any(|e| matches!(e.kind, EdgeKind::CG_CALLS | EdgeKind::REFERENCES))
}

fn check_symbol(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    if !is_fake_thoughtful_suffix(name) {
        return None;
    }
    if has_any_incoming(ctx, id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(SlopFindingBlueprint {
        rule_id: "cc.slop.unused_helper",
        category: Category::Slop,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("helper `{name}` is unused"),
        explanation: format!(
            "Function `{name}` is named like a helper (`*_helper` / \
             `*_util` / `*_manager` / `*_handler`) but has no incoming \
             references in this batch. Either inline its caller-of-one or \
             delete it."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Delete the helper, or rename and inline it where its single \
             intended caller actually uses it."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}

fn has_any_incoming(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let any_call = incoming_edges_of_kind(ctx.batch, id, EdgeKind::CG_CALLS)
        .next()
        .is_some();
    let any_ref = incoming_edges_of_kind(ctx.batch, id, EdgeKind::REFERENCES)
        .next()
        .is_some();
    any_call || any_ref
}
