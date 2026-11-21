//! `cc.arch.fan_in_outlier` — flag modules with too many incoming
//! imports (god hubs).
//!
//! Phase-3 limitation: rules see one batch (one file) at a time, so
//! "incoming imports" is computed from this batch's outgoing edges
//! mapped to every distinct *target*. A target whose batch-local fan-in
//! exceeds the threshold is reported. Repo-wide fan-in lands when
//! `RuleContext::project` grows a populated `LayerGraph` (Phase 4).

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, build_import_graph, enclosing_file_path, location_from_node,
    ArchitectureFindingBlueprint,
};

/// Default fan-in threshold. Hardcoded for Phase 3; configurable per-repo
/// via `cc-config` once the Phase-4 wiring lands.
pub const DEFAULT_FAN_IN_THRESHOLD: usize = 30;

/// Family-20 rule R-ARCH-FAN-IN.
#[derive(Debug, Default, Clone, Copy)]
pub struct FanInOutlierRule;

impl Rule for FanInOutlierRule {
    fn rule_id(&self) -> &'static str {
        "cc.arch.fan_in_outlier"
    }
    fn category(&self) -> Category {
        Category::Arch
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "module is imported by too many other modules (god hub)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let graph = build_import_graph(ctx.batch);
        let mut out = Vec::new();
        let mut targets: Vec<&String> = graph.edges().values().flatten().collect();
        targets.sort();
        targets.dedup();
        for target in targets {
            if graph.fan_in(target) > DEFAULT_FAN_IN_THRESHOLD {
                push_finding(ctx, target, graph.fan_in(target), &mut out);
            }
        }
        out
    }
}

fn push_finding(ctx: &RuleContext<'_>, target: &str, fan_in: usize, out: &mut Vec<Finding>) {
    let Some(file_id) = first_file_node(ctx) else {
        return;
    };
    let Some(path) = enclosing_file_path(ctx.batch, file_id) else {
        return;
    };
    let location = location_from_node(ctx.batch, file_id, path);
    out.push(build_finding(ArchitectureFindingBlueprint {
        rule_id: "cc.arch.fan_in_outlier",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        related: Vec::new(),
        headline: format!(
            "module `{target}` is a god hub: {fan_in} incoming imports (limit \
             {DEFAULT_FAN_IN_THRESHOLD})"
        ),
        explanation: format!(
            "{fan_in} other modules import `{target}`. A single hub with this \
             much fan-in becomes a refactor blast radius — every change to it \
             rebuilds the world. Split the surface so callers depend on \
             smaller, role-specific surfaces."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Split `target` into role-specific sub-modules; have each caller \
             import only the slice it needs. Aim for fan-in well under 30 per \
             leaf module."
                .into(),
        ),
        snippet: String::new(),
        weight: 2,
    }));
}

fn first_file_node(ctx: &RuleContext<'_>) -> Option<cc_cpg::NodeId> {
    for node in ctx.batch.nodes() {
        if node.kind == cc_cpg::NodeKind::File {
            return Some(node.id);
        }
    }
    None
}
