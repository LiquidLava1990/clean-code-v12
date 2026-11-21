//! `cc.supplychain.no_codeowners` — no `CODEOWNERS` file in any
//! accepted location.
//!
//! Heuristic: collect every [`NodeKind::File`] path in the batch. If
//! none of `CODEOWNERS`, `.github/CODEOWNERS`, `docs/CODEOWNERS` is
//! present, flag the repo. A `CODEOWNERS` file is the GitHub-native
//! way to require domain-expert review on sensitive paths.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    any_path_matches, build_finding, location_for_file, SupplyChainFindingBlueprint,
    GOVERNANCE_FILES_REQUIRED,
};

/// Family-32 probe R-SUPPLYCHAIN-NO-CODEOWNERS.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCodeownersRule;

impl Rule for NoCodeownersRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.no_codeowners"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deps
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.65)
    }
    fn description(&self) -> &'static str {
        "repo has no CODEOWNERS file in any accepted location"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let paths: Vec<Utf8PathBuf> = nodes_of_kind(ctx.batch, NodeKind::File)
            .filter_map(|node| string_prop(ctx.batch, node.id, "path").map(Utf8PathBuf::from))
            .collect();
        if paths.is_empty() {
            return Vec::new();
        }
        let candidates = codeowners_candidates();
        if any_path_matches(&paths, candidates) {
            return Vec::new();
        }
        vec![emit()]
    }
}

fn codeowners_candidates() -> &'static [&'static str] {
    GOVERNANCE_FILES_REQUIRED
        .iter()
        .find(|(name, _)| *name == "codeowners")
        .map_or(&[], |(_, files)| *files)
}

fn emit() -> Finding {
    let location = location_for_file(Utf8PathBuf::from("CODEOWNERS"), 1);
    build_finding(SupplyChainFindingBlueprint {
        rule_id: "cc.supplychain.no_codeowners",
        severity: Severity::Nit,
        confidence: Confidence::new(0.65),
        location,
        headline: "Repo has no `CODEOWNERS` file".into(),
        explanation: "No `CODEOWNERS` file exists at the root, `.github/`, or \
             `docs/`. Without it, GitHub cannot auto-request review from \
             domain experts on sensitive paths (auth, crypto, build \
             pipeline) and Scorecard's `Code-Review` signal stays \
             unsatisfied for high-risk merges."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add `.github/CODEOWNERS` listing path globs and the GitHub \
             handles / teams responsible for them. Keep it short — \
             coarse-grained ownership lines beat exhaustive ones that \
             nobody updates."
                .into(),
        ),
        snippet: "missing CODEOWNERS".into(),
        weight: 1,
    })
}
