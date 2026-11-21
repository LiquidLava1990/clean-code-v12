//! `cc.bug.off_by_one` — index-arithmetic patterns inside numeric loops.
//!
//! Heuristic: every [`NodeKind::Loop`] whose `header` string property
//! matches `for i in 0..len(<xs>)` / `for i in range(len(<xs>))` /
//! `for (let i = 0; i < xs.length; …)` is searched. The loop is flagged
//! when the body contains either:
//!
//! - `<xs>[i+1]` / `<xs>[i + 1]` — out-of-bounds risk on the last iter.
//! - `<xs>[i-1]` / `<xs>[i - 1]` without a guarding `i > 0` predicate.
//!
//! Frontends inconsistently expose the loop body verbatim, so this probe
//! relies on the source bytes inside the loop's `range` property when
//! present. Body-text gaps degrade gracefully (no finding) instead of
//! crashing.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node, BugFindingBlueprint,
};

/// Family-3 probe R-OFF-BY-ONE.
#[derive(Debug, Default, Clone, Copy)]
pub struct OffByOneRule;

impl Rule for OffByOneRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.off_by_one"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "loop body indexes the collection with i+1 or i-1 without a guard"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Loop) {
            if let Some(finding) = check_loop(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_loop(ctx: &RuleContext<'_>, loop_id: NodeId) -> Option<Finding> {
    let header = string_prop(ctx.batch, loop_id, "header").unwrap_or("");
    if !is_indexed_loop(header) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, loop_id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let body = body_text(ctx, loop_id, &path)?;
    let kind = classify_body(&body)?;
    let location = location_from_node(ctx.batch, loop_id, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.off_by_one",
        severity: Severity::Required,
        confidence: Confidence::new(0.6),
        location,
        headline: format!("indexed loop accesses `{kind}` without a bounds guard"),
        explanation: format!(
            "The loop body uses `{kind}` while iterating from 0 to len(xs); \
             on the boundary iteration this either reads past the end \
             (`i+1`) or wraps to a negative index (`i-1` with no `i > 0` \
             guard). Both manifest as IndexError / panic at runtime."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Iterate over `xs.windows(2)` / `zip(xs, xs[1..])` / \
             `for (a, b) in pairs(xs)` instead of indexing arithmetic, or \
             tighten the loop bound (`0..len(xs).saturating_sub(1)`) and \
             guard `i-1` accesses with `if i > 0`."
                .into(),
        ),
        snippet: header.to_owned(),
        weight: 2,
    }))
}

fn is_indexed_loop(header: &str) -> bool {
    let h = header.replace(' ', "");
    h.contains("for") && (h.contains("0..len(") || h.contains("range(len("))
        || h.contains("0;i<") && h.contains(".length")
}

fn body_text(ctx: &RuleContext<'_>, loop_id: NodeId, path: &camino::Utf8PathBuf) -> Option<String> {
    let range = range_prop(ctx.batch, loop_id, "range")?;
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return None;
    }
    let start = range.start.offset as usize;
    let end = (range.end.offset as usize).min(bytes.len()).max(start);
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(str::to_owned)
}

fn classify_body(body: &str) -> Option<&'static str> {
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.contains("[i+1]") {
        return Some("xs[i+1]");
    }
    if cleaned.contains("[i-1]") && !cleaned.contains("ifi>0") && !cleaned.contains("i>0&&") {
        return Some("xs[i-1]");
    }
    None
}
