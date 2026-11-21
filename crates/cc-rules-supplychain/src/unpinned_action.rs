//! `cc.supplychain.unpinned_action` — GitHub Action used by tag/branch.
//!
//! Heuristic: walk every [`NodeKind::File`] whose path matches
//! `.github/workflows/*.yml`. Scan the source bytes line-by-line for
//! `uses: <repo>@<ref>` declarations and flag any `<ref>` that is not a
//! 40-character SHA-1 hex. Tag refs (e.g. `actions/checkout@v4`) and
//! branch refs (e.g. `actions/checkout@main`) are mutable — the action
//! author can re-tag, the registry can be compromised, and Scorecard
//! `Pinned-Dependencies` is the canonical control here.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_sha1_hex, is_workflow_path, location_for_file, SupplyChainFindingBlueprint,
};

/// Family-32 probe R-SUPPLYCHAIN-UNPINNED-ACTION.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnpinnedActionRule;

impl Rule for UnpinnedActionRule {
    fn rule_id(&self) -> &'static str {
        "cc.supplychain.unpinned_action"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deps
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "GitHub Action pinned by tag/branch instead of immutable SHA"
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
    if !is_workflow_path(&path) {
        return;
    }
    let bytes = ctx.source.get(path.as_path());
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        if let Some((repo, reference)) = parse_uses_line(line) {
            if !is_sha1_hex(reference) {
                let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
                out.push(emit(&path, line_no, line.trim(), repo, reference));
            }
        }
    }
}

/// Parse `uses: <repo>@<ref>` from a workflow line, ignoring inline
/// comments. Returns `(repo, ref)` when matched. Handles the common
/// YAML list-item form (`- uses: ...`) by stripping a leading `-`.
fn parse_uses_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim_start();
    // Strip a leading list-item dash so `- uses: ...` parses too.
    let trimmed = trimmed.strip_prefix('-').map_or(trimmed, str::trim_start);
    let rest = trimmed.strip_prefix("uses:")?.trim_start();
    // Strip optional surrounding quotes.
    let rest = rest.trim_matches(|c: char| c == '"' || c == '\'');
    // Drop any trailing inline comment.
    let rest = rest.split('#').next()?.trim();
    let (repo, reference) = rest.split_once('@')?;
    let reference = reference.trim_matches(|c: char| c == '"' || c == '\'');
    if repo.is_empty() || reference.is_empty() {
        return None;
    }
    // Skip local actions (`./.github/actions/foo`) and docker refs —
    // pinning rules differ. Both contain a `/` in `repo` but local
    // refs start with `.`.
    if repo.starts_with('.') || repo.starts_with("docker://") {
        return None;
    }
    Some((repo, reference))
}

fn emit(path: &Utf8PathBuf, line_no: u32, line: &str, repo: &str, reference: &str) -> Finding {
    let location = location_for_file(path.clone(), line_no);
    build_finding(SupplyChainFindingBlueprint {
        rule_id: "cc.supplychain.unpinned_action",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("`uses: {repo}@{reference}` is not pinned to a SHA"),
        explanation: format!(
            "Workflow `{}` references `{repo}@{reference}`. Tag and branch \
             refs are mutable: the action author can re-tag (intentionally \
             or after a registry compromise) and your CI silently runs \
             different code on the next run. Scorecard's Pinned-Dependencies \
             control requires a 40-character SHA-1 commit id.",
            path.as_str()
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace `{reference}` with the 40-character SHA the tag points \
             at today, and keep the tag in a comment for human readability: \
             `uses: {repo}@<sha>  # {reference}`. Renovate / Dependabot can \
             automate the bump-with-SHA dance."
        )),
        snippet: line.to_owned(),
        weight: 4,
    })
}
