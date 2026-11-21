//! `cc.slop.fake_thoughtful_name` — flag identifiers ending in vague
//! suffixes that pretend to add semantics without doing so.
//!
//! Phase-2 heuristic: any function / method / class / variable whose
//! name matches `*_helper(s)`, `*_util(s)`, `*_manager`, or `*_handler`
//! (case-insensitive). Bare `helper` (no prefix) is allowed because the
//! signal is the *suffix on a real name*, not the word itself.
//!
//! Skips: identifiers under 4 chars, names starting with `_`
//! (private/dunder), names whose prefix is empty (e.g. `_helper`).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_fake_thoughtful_suffix, is_test_file_path,
    location_from_node, SlopFindingBlueprint,
};

/// Family-1 rule R-SLOP-NAME.
#[derive(Debug, Default, Clone, Copy)]
pub struct FakeThoughtfulNameRule;

impl Rule for FakeThoughtfulNameRule {
    fn rule_id(&self) -> &'static str {
        "cc.slop.fake_thoughtful_name"
    }
    fn category(&self) -> Category {
        Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "identifier uses a vague *_helper / *_util / *_manager / *_handler suffix"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [
            NodeKind::Function,
            NodeKind::Method,
            NodeKind::Class,
            NodeKind::Variable,
        ] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_name(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_name(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    if name.starts_with('_') || name.len() < 4 {
        return None;
    }
    if !is_fake_thoughtful_suffix(name) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        // Test fixtures intentionally use *_helper / *_handler names to
        // exercise this very rule — flagging them is rule-on-rule noise.
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(SlopFindingBlueprint {
        rule_id: "cc.slop.fake_thoughtful_name",
        category: Category::Slop,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("identifier `{name}` uses a vague catch-all suffix"),
        explanation: format!(
            "Names like `{name}` describe scaffolding, not behaviour. \
             `*_helper` / `*_util` / `*_manager` / `*_handler` defer the \
             question 'what does it do?' instead of answering it."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Rename `{name}` to describe the actual behaviour \
             (e.g. `parse_token` instead of `token_helper`, `route_request` \
             instead of `request_handler`)."
        )),
        snippet: String::new(),
        weight: 1,
    }))
}
