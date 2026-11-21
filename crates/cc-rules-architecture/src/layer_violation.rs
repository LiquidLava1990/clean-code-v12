//! `cc.arch.layer_violation` — downward-only import doctrine.
//!
//! For every [`NodeKind::Import`] in the batch we resolve the
//! source-module (the file *doing* the import) and the target-module
//! (the import's own resolved target). If the per-batch
//! [`crate::helpers::ImportGraph`] reports the edge would close a cycle
//! — i.e. it is *not* downward-only — we flag the Import.
//!
//! Phase-3 conservatism: the rule is silent for any Import whose
//! target the frontend could not resolve (no `target_module` /
//! `source` / `path` / `name` prop). This avoids mass-flagging stdlib
//! imports the frontend has only partially resolved.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, build_import_graph, enclosing_file_path, location_from_node, source_module_name,
    target_module_for_import, ArchitectureFindingBlueprint, ImportGraph,
};

/// Family-20 rule R-ARCH-LAYER.
#[derive(Debug, Default, Clone, Copy)]
pub struct LayerViolationRule;

impl Rule for LayerViolationRule {
    fn rule_id(&self) -> &'static str {
        "cc.arch.layer_violation"
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
        "import violates the downward-only layering doctrine"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let Some(source) = source_module_name(ctx.batch) else {
            return Vec::new();
        };
        let graph = build_import_graph(ctx.batch);
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Import) {
            if let Some(finding) = check_import(ctx, &graph, &source, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_import(
    ctx: &RuleContext<'_>,
    graph: &ImportGraph,
    source: &str,
    import_id: NodeId,
) -> Option<Finding> {
    let target = target_module_for_import(ctx.batch, import_id)?;
    if graph.is_downward_only(source, &target) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, import_id)?;
    let location = location_from_node(ctx.batch, import_id, path);
    Some(build_finding(ArchitectureFindingBlueprint {
        rule_id: "cc.arch.layer_violation",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        related: Vec::new(),
        headline: format!(
            "module `{source}` imports `{target}` against the downward-only doctrine"
        ),
        explanation: format!(
            "`{source}` -> `{target}` either inverts the layering (a shallower \
             module reaches into a deeper one) or closes a cycle in the recorded \
             import graph. Layer inversions break the dependency-injection \
             contract that lets deeper modules be swapped without churning \
             shallower ones."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Move the imported symbol up to a shared layer both modules can \
             depend on, invert the dependency via a trait / interface, or \
             delete the import if the coupling is incidental."
                .into(),
        ),
        snippet: format!("import {target}"),
        weight: 3,
    }))
}
