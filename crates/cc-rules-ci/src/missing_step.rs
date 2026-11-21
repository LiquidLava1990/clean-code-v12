//! `cc.ci.missing_step` — CI workflow missing lint/test/typecheck.
//!
//! Heuristic: walk every [`NodeKind::File`] whose path matches a CI
//! workflow pattern (`.github/workflows/*.yml`, `.gitlab-ci.yml`,
//! `azure-pipelines.yml`, `bitbucket-pipelines.yml`,
//! `.circleci/config.yml`). Inspect the source bytes; if the workflow
//! does NOT mention any of the required step keywords, flag it.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_ci_workflow_path, location_for_file, CiFindingBlueprint,
    REQUIRED_STEP_KEYWORDS,
};

/// Family-17 probe R-CI-MISSING-STEP.
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingStepRule;

impl Rule for MissingStepRule {
    fn rule_id(&self) -> &'static str {
        "cc.ci.missing_step"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Ci
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "CI workflow file does not mention lint, test, or typecheck"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            scan_file(ctx, node.id, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, file_id: NodeId, out: &mut Vec<Finding>) {
    let Some(raw) = string_prop(ctx.batch, file_id, "path") else {
        return;
    };
    let path = Utf8PathBuf::from(raw);
    if !is_ci_workflow_path(&path) {
        return;
    }
    let bytes = ctx.source.get(path.as_path());
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if text.trim().is_empty() {
        return;
    }
    let lower = text.to_ascii_lowercase();
    if REQUIRED_STEP_KEYWORDS
        .iter()
        .any(|k| has_keyword(&lower, k))
    {
        return;
    }
    out.push(emit(&path));
}

/// Substring-with-word-boundary check. The keyword matches only when the
/// surrounding bytes are not ASCII alphanumerics — this avoids treating
/// `ubuntu-latest` as a `test` mention.
fn has_keyword(text: &str, keyword: &str) -> bool {
    let bytes = text.as_bytes();
    let kw = keyword.as_bytes();
    if kw.is_empty() || bytes.len() < kw.len() {
        return false;
    }
    for start in 0..=bytes.len() - kw.len() {
        if &bytes[start..start + kw.len()] != kw {
            continue;
        }
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_idx = start + kw.len();
        let after_ok = after_idx == bytes.len() || !bytes[after_idx].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

fn emit(path: &Utf8PathBuf) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(CiFindingBlueprint {
        rule_id: "cc.ci.missing_step",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!(
            "CI workflow `{}` runs no lint/test/typecheck step",
            path.as_str()
        ),
        explanation: format!(
            "Workflow `{}` exists but mentions none of `lint`, `test`, or \
             `typecheck`. A CI pipeline that does not run those gates \
             provides no signal about the change being merged. Either add \
             the missing steps or, if this workflow is purely a deploy \
             trigger, rename it to make that intent obvious and exempt it \
             via configuration.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add a job that runs the project's lint, type-check, and test \
             suites. For GitHub Actions, this is usually a `steps:` block \
             with `run: <project test command>`. Wire it onto `pull_request` \
             so PRs are gated."
                .into(),
        ),
        snippet: path.as_str().to_owned(),
        weight: 3,
    })
}
