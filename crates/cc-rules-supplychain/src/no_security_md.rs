//! `cc.supplychain.no_security_md` — no `SECURITY.md` policy file.
//!
//! Heuristic: collect every [`NodeKind::File`] path in the batch. If
//! none of `SECURITY.md`, `.github/SECURITY.md`, `docs/SECURITY.md`
//! is present, flag the repo. A `SECURITY.md` is the standard
//! channel for coordinated vulnerability disclosure.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    any_path_matches, build_finding, location_for_file, SupplyChainFindingBlueprint,
    GOVERNANCE_FILES_REQUIRED,
};

/// Family-32 probe R-SUPPLYCHAIN-NO-SECURITY-MD.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSecurityMdRule;

impl Rule for NoSecurityMdRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.no_security_md"
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
        "repo has no SECURITY.md disclosure-policy file"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let paths: Vec<Utf8PathBuf> = nodes_of_kind(ctx.batch, NodeKind::File)
            .filter_map(|node| string_prop(ctx.batch, node.id, "path").map(Utf8PathBuf::from))
            .collect();
        if paths.is_empty() {
            return Vec::new();
        }
        let candidates = security_md_candidates();
        if any_path_matches(&paths, candidates) {
            return Vec::new();
        }
        vec![emit()]
    }
}

fn security_md_candidates() -> &'static [&'static str] {
    GOVERNANCE_FILES_REQUIRED
        .iter()
        .find(|(name, _)| *name == "security_md")
        .map_or(&[], |(_, files)| *files)
}

fn emit() -> Finding {
    let location = location_for_file(Utf8PathBuf::from("SECURITY.md"), 1);
    build_finding(SupplyChainFindingBlueprint {
        rule_id: "cc.supplychain.no_security_md",
        severity: Severity::Nit,
        confidence: Confidence::new(0.65),
        location,
        headline: "Repo has no `SECURITY.md`".into(),
        explanation: "No `SECURITY.md` exists at the root, `.github/`, or `docs/`. \
             Researchers reporting vulnerabilities have no documented \
             channel and Scorecard's `Security-Policy` signal fails. The \
             absence often forces public issue-tracker disclosure, which \
             is the worst possible outcome for both reporter and project."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add `SECURITY.md` describing: (1) which versions receive \
             security fixes, (2) how to report a vulnerability privately \
             (email, GitHub Security Advisories), (3) the expected \
             acknowledgement / triage timeline."
                .into(),
        ),
        snippet: "missing SECURITY.md".into(),
        weight: 1,
    })
}
