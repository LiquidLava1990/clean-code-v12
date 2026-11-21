//! `cc.chain.fn_in_pathway_no_registry` — fn appears in a "pathway"
//! (canonical workflow YAML) but isn't in the meta-registry.
//!
//! Phase-2 status: STUB. Pathway YAMLs (`pathways.yaml`, `loops.yaml`)
//! sit outside the per-file `RuleContext`. Resolving cross-file
//! references requires the persistent CPG store (Phase 3 W1.T3).
//!
//! TODO(phase-3): load `pathways.yaml` via the kernel and join against
//! decorator-walker output to flag pathway members without
//! `@meta_async`/`@trace_async`.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Probe `cc.chain.fn_in_pathway_no_registry` (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct FnInPathwayNoRegistryRule;

impl Rule for FnInPathwayNoRegistryRule {
    fn rule_id(&self) -> &'static str {
        "cc.chain.fn_in_pathway_no_registry"
    }
    fn category(&self) -> Category {
        Category::Arch
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "fn in pathways.yaml has no meta-registry decorator (stub — Phase 3)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-3): load pathways.yaml and cross-reference.
        Vec::new()
    }
}
