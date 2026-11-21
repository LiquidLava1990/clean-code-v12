//! `cc.arch.layer_violation_import` — domain-layer file imports from
//! infrastructure-layer file.
//!
//! Hexagonal / clean-architecture doctrine: the **domain** (entities +
//! business rules) is the deepest, purest layer and must NOT depend on
//! infrastructure (databases, HTTP clients, message queues). Infrastructure
//! depends on domain via trait/interface inversion, not the other way
//! round.
//!
//! Sister probe to [`crate::layer_violation`] — which uses the
//! per-batch import graph to flag *any* upward import. This probe is a
//! **path-component** heuristic: the source file lives in a path
//! containing a `domain` segment AND the imported target's resolved
//! string contains an `infrastructure` segment. Required, 0.85.
//!
//! OSS source: ArchUnit `noClasses().that().resideInAPackage("..domain..")
//! .should().dependOnClassesThat().resideInAPackage("..infrastructure..")`,
//! Sonar S5803, dependency-cruiser `no-orphans` / layer rules.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, target_module_for_import,
    ArchitectureFindingBlueprint,
};

/// Family-20 probe `cc.arch.layer_violation_import`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LayerViolationImportRule;

const DOMAIN_SEGMENTS: &[&str] = &["/domain/", "/domains/", "/core/", "/entities/"];
const INFRA_SEGMENTS: &[&str] = &[
    "/infrastructure/",
    "/infra/",
    "infrastructure.",
    "infra.",
    "::infrastructure::",
    "::infra::",
];

impl Rule for LayerViolationImportRule {
    fn rule_id(&self) -> &'static str {
        "cc.arch.layer_violation_import"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Arch
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "domain-layer file imports infrastructure-layer module — clean-architecture inversion"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Import) {
            if let Some(finding) = check_import(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_import(ctx: &RuleContext<'_>, import_id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, import_id)?;
    let source_path = path.as_str().replace('\\', "/").to_ascii_lowercase();
    if !DOMAIN_SEGMENTS.iter().any(|seg| source_path.contains(seg)) {
        return None;
    }
    let target = target_module_for_import(ctx.batch, import_id)?;
    let target_lower = target.to_ascii_lowercase();
    if !INFRA_SEGMENTS.iter().any(|seg| target_lower.contains(seg)) {
        return None;
    }
    Some(emit_finding(ctx, import_id, &path, &target))
}

fn emit_finding(
    ctx: &RuleContext<'_>,
    import_id: NodeId,
    path: &camino::Utf8PathBuf,
    target: &str,
) -> Finding {
    let location = location_from_node(ctx.batch, import_id, path.clone());
    build_finding(ArchitectureFindingBlueprint {
        rule_id: "cc.arch.layer_violation_import",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        related: Vec::new(),
        headline: format!(
            "domain file imports infrastructure module `{target}` — \
             layering inverted"
        ),
        explanation: "Files under a `domain/` (or `core/` / `entities/`) \
             path component represent business rules and must not depend \
             on infrastructure (databases, HTTP clients, message queues). \
             Infrastructure depends on domain via trait/interface \
             inversion. The current import couples the pure layer to a \
             concrete adapter, making the domain unswappable and \
             untestable without the infrastructure stack."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Define a port (trait / interface / Protocol) in the domain \
             layer; have the infrastructure module implement it; inject \
             the implementation at the composition root. The domain \
             never names the infrastructure type directly."
                .into(),
        ),
        snippet: format!("import {target}"),
        weight: 5,
    })
}
