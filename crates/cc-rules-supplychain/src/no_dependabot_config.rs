//! `cc.supplychain.no_dependabot_config` — manifests present, no
//! Dependabot config.
//!
//! Heuristic: collect every [`NodeKind::File`] path in the batch. If
//! the repo carries any of [`MANIFEST_FILES`] but none of the accepted
//! Dependabot config locations, emit a single repo-level Nit. A repo
//! without automated dependency PRs accumulates CVE exposure quietly.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    any_path_matches, build_finding, has_any_manifest, location_for_file,
    SupplyChainFindingBlueprint, GOVERNANCE_FILES_REQUIRED,
};

/// Family-32 probe R-SUPPLYCHAIN-NO-DEPENDABOT-CONFIG.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDependabotConfigRule;

impl Rule for NoDependabotConfigRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.no_dependabot_config"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deps
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "manifests present but no .github/dependabot.yml committed"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let paths: Vec<Utf8PathBuf> = nodes_of_kind(ctx.batch, NodeKind::File)
            .filter_map(|node| string_prop(ctx.batch, node.id, "path").map(Utf8PathBuf::from))
            .collect();
        if !has_any_manifest(&paths) {
            return Vec::new();
        }
        let candidates = dependabot_candidates();
        if any_path_matches(&paths, candidates) {
            return Vec::new();
        }
        vec![emit(&paths)]
    }
}

fn dependabot_candidates() -> &'static [&'static str] {
    GOVERNANCE_FILES_REQUIRED
        .iter()
        .find(|(name, _)| *name == "dependabot")
        .map_or(&[], |(_, files)| *files)
}

fn emit(paths: &[Utf8PathBuf]) -> Finding {
    // Anchor on the first manifest path we know about so the finding
    // surfaces near the manifest in IDE views.
    let anchor = paths
        .iter()
        .find(|p| {
            p.file_name()
                .is_some_and(|n| matches!(n, "Cargo.toml" | "package.json" | "go.mod"))
        })
        .cloned()
        .unwrap_or_else(|| Utf8PathBuf::from("."));
    let location = location_for_file(anchor.clone(), 1);
    build_finding(SupplyChainFindingBlueprint {
        rule_id: "cc.supplychain.no_dependabot_config",
        severity: Severity::Nit,
        confidence: Confidence::new(0.7),
        location,
        headline: "Repo has manifests but no `.github/dependabot.yml`".into(),
        explanation: "Dependency manifests are present but `.github/dependabot.yml` \
             (or `dependabot.yaml`) is missing. Without an automated bump \
             pipeline (Dependabot or Renovate), CVE advisories stay open \
             until a human notices — Scorecard's `Maintained` and \
             `Vulnerabilities` signals both penalise this."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Commit `.github/dependabot.yml` with a `version: 2` config \
             listing each ecosystem in use (e.g. `cargo`, `npm`, \
             `gomod`, `pip`, `github-actions`) on a weekly schedule. \
             Renovate's `renovate.json` is an acceptable substitute — \
             extend this rule's config to recognise it."
                .into(),
        ),
        snippet: anchor.as_str().to_owned(),
        weight: 1,
    })
}
