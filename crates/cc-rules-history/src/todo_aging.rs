//! `cc.rot.todo_aging` — flag aging-marker comments (`TODO` / `FIXME` /
//! `XXX` / `HACK`).
//!
//! The full semantic of the rule is "comment older than 90 days as
//! computed via `git blame`". Phase 4 does not yet expose git plumbing
//! through [`cc_rules::RuleContext`], so this implementation ships a
//! non-aging variant: every aging-marker comment is reported as
//! [`Severity::Nit`]. Each finding represents a deferred-work item that
//! should be either resolved or converted into a tracked issue.
//!
//! TODO(phase-5): wire git blame so the probe escalates to
//! [`Severity::Required`] only when the comment exceeds the
//! configurable age threshold (default 90 days).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    aging_marker, build_finding, enclosing_file_path, location_from_node,
    looks_like_rule_pack_source, HistoryFindingBlueprint,
};

/// Family-18 probe R-ROT-TODO-AGING (non-aging Phase-4 variant).
#[derive(Debug, Default, Clone, Copy)]
pub struct TodoAgingRule;

impl Rule for TodoAgingRule {
    fn rule_id(&self) -> &'static str {
        "cc.rot.todo_aging"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Rot
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "TODO / FIXME / XXX / HACK comment (Phase-4 non-aging variant)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Comment) {
            if let Some(finding) = check_comment(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_comment(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let text = comment_text(ctx, id)?;
    let marker = aging_marker(text)?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if looks_like_rule_pack_source(&path) {
        // TODO comments inside the kernel's own rule packs document
        // intentional Phase-N follow-up work; treat them as deferred
        // backlog rather than rot signals on the host codebase.
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(HistoryFindingBlueprint {
        rule_id: "cc.rot.todo_aging",
        severity: Severity::Nit,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("`{marker}` comment — convert or resolve"),
        explanation: format!(
            "Comment carries the aging marker `{marker}`. The Phase-4 \
             implementation cannot read git history, so every such \
             comment is surfaced as a `Nit`; the Phase-5 implementation \
             will escalate to `Required` only once the comment is older \
             than the configured age threshold (default 90 days). Each \
             marker represents deferred work that should be either \
             resolved in this change or converted into a tracked issue."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Either complete the work the `{marker}` describes, replace \
             the marker with an issue link (e.g. `// see #1234 for \
             follow-up`), or delete the comment if it is obsolete."
        )),
        snippet: text.lines().next().unwrap_or(text).to_owned(),
        weight: 1,
    }))
}

fn comment_text<'b>(ctx: &RuleContext<'b>, id: NodeId) -> Option<&'b str> {
    string_prop(ctx.batch, id, "text").or_else(|| string_prop(ctx.batch, id, "value"))
}
