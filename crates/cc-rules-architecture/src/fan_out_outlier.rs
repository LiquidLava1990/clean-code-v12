//! `cc.arch.fan_out_outlier` — flag modules that import too many other
//! modules (god dispatchers).
//!
//! Counts outgoing edges per source-module in the per-batch
//! `crate::helpers::ImportGraph`; threshold defaults to
//! [`DEFAULT_FAN_OUT_THRESHOLD`].

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, build_import_graph, enclosing_file_path, location_from_node, source_module_name,
    ArchitectureFindingBlueprint,
};

/// Default fan-out threshold. Hardcoded for Phase 3.
pub const DEFAULT_FAN_OUT_THRESHOLD: usize = 25;

/// Family-20 rule R-ARCH-FAN-OUT.
#[derive(Debug, Default, Clone, Copy)]
pub struct FanOutOutlierRule;

impl Rule for FanOutOutlierRule {
    fn rule_id(&self) -> &'static str {
        "cc.arch.fan_out_outlier"
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
        "module imports too many others (god dispatcher)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let Some(source) = source_module_name(ctx.batch) else {
            return Vec::new();
        };
        let graph = build_import_graph(ctx.batch);
        let fan_out = graph.fan_out(&source);
        if fan_out <= DEFAULT_FAN_OUT_THRESHOLD {
            return Vec::new();
        }
        emit(ctx, &source, fan_out).into_iter().collect()
    }
}

fn emit(ctx: &RuleContext<'_>, source: &str, fan_out: usize) -> Option<Finding> {
    let file_id = first_file_node(ctx)?;
    let path = enclosing_file_path(ctx.batch, file_id)?;
    let location = location_from_node(ctx.batch, file_id, path);
    Some(build_finding(ArchitectureFindingBlueprint {
        rule_id: "cc.arch.fan_out_outlier",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        related: Vec::new(),
        headline: format!(
            "module `{source}` is a god dispatcher: {fan_out} outgoing imports \
             (limit {DEFAULT_FAN_OUT_THRESHOLD})"
        ),
        explanation: format!(
            "`{source}` imports {fan_out} other modules. A single module reaching \
             into this many neighbours either knows too much (split it) or owns \
             a coordination surface that should live behind a typed boundary."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Split `source` into role-specific sub-modules, or hide the coordination \
             surface behind a typed orchestrator. Aim for fan-out under 25 per file."
                .into(),
        ),
        snippet: String::new(),
        weight: 2,
    }))
}

fn first_file_node(ctx: &RuleContext<'_>) -> Option<cc_cpg::NodeId> {
    for node in ctx.batch.nodes() {
        if node.kind == cc_cpg::NodeKind::File {
            return Some(node.id);
        }
    }
    None
}
