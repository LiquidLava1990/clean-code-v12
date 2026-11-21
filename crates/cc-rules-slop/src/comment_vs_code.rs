//! `cc.slop.comment_vs_code` — flag comments whose claimed behaviour is
//! contradicted by the function name.
//!
//! TODO(phase-5-llm): the deep semantic check (does the body actually do
//! what the comment says?) is deferred to the LLM family. Phase 2 ships
//! a pure-string heuristic.
//!
//! Heuristic: when a function carries a doc-style comment containing
//! "returns X" or "return X" but the function name negates X (e.g.
//! `is_empty` with comment "returns the value"), flag it. We use a
//! conservative pattern set so that false positives stay rare.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, SlopFindingBlueprint,
};

/// Phase-2 heuristic for R-SLOP-COMMENT-VS-CODE.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommentVsCodeRule;

impl Rule for CommentVsCodeRule {
    fn rule_id(&self) -> &'static str {
        "cc.slop.comment_vs_code"
    }
    fn category(&self) -> Category {
        Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.88)
    }
    fn description(&self) -> &'static str {
        "doc comment claims a behaviour that the function name contradicts"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    let docstring = string_prop(ctx.batch, id, "docstring")?;
    if !contradicts(name, docstring) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(SlopFindingBlueprint {
        rule_id: "cc.slop.comment_vs_code",
        category: Category::Slop,
        severity: Severity::Required,
        confidence: Confidence::new(0.88),
        location,
        headline: format!("doc comment on `{name}` contradicts its name"),
        explanation: format!(
            "Function `{name}` has a name that strongly suggests one \
             behaviour, but its doc comment describes a different one. \
             Either the comment is stale, or the function is mis-named."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Rewrite the doc comment to match what the code does, or rename \
             the function so the name describes its actual behaviour."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}

/// Conservative contradiction patterns. Each pair is `(name_predicate,
/// comment_marker)` — when the function name satisfies the predicate AND
/// the doc comment contains the marker (case-insensitive), we flag.
fn contradicts(name: &str, doc: &str) -> bool {
    let lower_doc = doc.to_ascii_lowercase();
    let lower_name = name.to_ascii_lowercase();

    // is_*/has_*/should_* should return a bool — comments saying "returns
    // the X" / "returns a list" / "returns a dict" contradict that.
    let is_predicate = lower_name.starts_with("is_")
        || lower_name.starts_with("has_")
        || lower_name.starts_with("should_")
        || lower_name.starts_with("can_");
    if is_predicate {
        for marker in [
            "returns the",
            "returns a list",
            "returns a dict",
            "returns a map",
        ] {
            if lower_doc.contains(marker) {
                return true;
            }
        }
    }

    // get_*/fetch_*/load_*/read_* are getters — comments saying "writes",
    // "deletes", "removes", or "modifies" contradict the getter contract.
    let is_getter = lower_name.starts_with("get_")
        || lower_name.starts_with("fetch_")
        || lower_name.starts_with("load_")
        || lower_name.starts_with("read_");
    if is_getter {
        for marker in ["writes", "deletes", "removes", "modifies", "mutates"] {
            if lower_doc.contains(marker) {
                return true;
            }
        }
    }
    false
}
