//! `cc.arch.circular_import` — Kahn's-algorithm cycle detection on the
//! per-batch import graph.
//!
//! We build the graph once via [`crate::helpers::build_import_graph`],
//! drain every zero-in-degree node via Kahn's algorithm, and any
//! module still standing is in a cycle. Each cycle member is flagged
//! with `related` pointing at the other cycle members so the user
//! can see the whole loop in one finding.

use cc_cpg::NodeKind;
use cc_finding::{
    Category, Confidence, Finding, Location, Position, RelatedLocation, Remediation, Severity,
};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, build_import_graph, enclosing_file_id, enclosing_file_path, kahn_cycle_members,
    location_from_node, source_module_name, target_module_for_import, ArchitectureFindingBlueprint,
};

/// Family-20 rule R-ARCH-CYCLE.
#[derive(Debug, Default, Clone, Copy)]
pub struct CircularImportRule;

impl Rule for CircularImportRule {
    fn rule_id(&self) -> &'static str {
        "cc.arch.circular_import"
    }
    fn category(&self) -> Category {
        Category::Arch
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "module participates in a circular import group"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let Some(source) = source_module_name(ctx.batch) else {
            return Vec::new();
        };
        let graph = build_import_graph(ctx.batch);
        let cycle_members = kahn_cycle_members(&graph);
        if !cycle_members.iter().any(|m| m == &source) {
            return Vec::new();
        }
        emit_for_source(ctx, &source, &cycle_members)
            .into_iter()
            .collect()
    }
}

fn emit_for_source(
    ctx: &RuleContext<'_>,
    source: &str,
    cycle_members: &[String],
) -> Option<Finding> {
    let file_id = locate_file_node(ctx)?;
    let path = enclosing_file_path(ctx.batch, file_id)?;
    let location = location_from_node(ctx.batch, file_id, path);
    let related = related_for_cycle(&location, source, cycle_members);
    let partners = cycle_partners(source, cycle_members);
    Some(build_finding(ArchitectureFindingBlueprint {
        rule_id: "cc.arch.circular_import",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.95),
        location,
        related,
        headline: format!("module `{source}` is in a circular-import cycle with {partners}"),
        explanation: format!(
            "Kahn's algorithm could not topologically sort the import graph; \
             `{source}` and its cycle partners ({partners}) all retain \
             non-zero in-degree after every sink drains. Circular imports \
             defeat partial-load semantics, defeat layering, and tend to \
             explode at module-init time."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Break the cycle by extracting the shared surface to a third \
             module both sides depend on, or invert one direction via a \
             trait / interface defined alongside the consumer."
                .into(),
        ),
        snippet: String::new(),
        weight: 5,
    }))
}

fn locate_file_node(ctx: &RuleContext<'_>) -> Option<cc_cpg::NodeId> {
    for node in ctx.batch.nodes() {
        if node.kind == NodeKind::File {
            return Some(node.id);
        }
        if node.kind == NodeKind::Import {
            return enclosing_file_id(ctx.batch, node.id);
        }
    }
    None
}

fn cycle_partners(source: &str, cycle_members: &[String]) -> String {
    let names: Vec<&str> = cycle_members
        .iter()
        .filter(|m| m.as_str() != source)
        .map(String::as_str)
        .collect();
    if names.is_empty() {
        "(self)".to_owned()
    } else {
        names.join(", ")
    }
}

fn related_for_cycle(
    primary: &Location,
    source: &str,
    cycle_members: &[String],
) -> Vec<RelatedLocation> {
    let mut out = Vec::new();
    let zero = Position::new(1, 1, 0);
    for partner in cycle_members {
        if partner == source {
            continue;
        }
        let location = Location {
            file: primary.file.clone(),
            start: zero,
            end: zero,
            node_id: None,
            function_qualified_name: Some(partner.clone()),
        };
        out.push(RelatedLocation {
            location,
            message: format!("cycle partner `{partner}`"),
        });
    }
    out
}

/// Diagnostic helper used by the unit tests: returns `(source, cycle)`.
#[must_use]
pub fn diag_resolve(ctx: &RuleContext<'_>) -> Option<(String, Vec<String>)> {
    // NOTE: target_module_for_import is currently only used by the
    // sibling layer_violation probe; we keep an unused-import canary
    // here to make linker-style dead-code stripping a no-op for tests.
    let _ = target_module_for_import;
    let source = source_module_name(ctx.batch)?;
    let graph = build_import_graph(ctx.batch);
    Some((source, kahn_cycle_members(&graph)))
}
