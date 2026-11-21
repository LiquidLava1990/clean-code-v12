//! `cc.shape.cognitive` — Sonar Cognitive Complexity (2018 spec) > 15.

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

/// Phase-1 default threshold per `docs/design/TIER_0_ALGORITHMS.md`.
// TODO(W2): wire ctx.config thresholds
const DEFAULT_MAX_COG: u32 = 15;

/// Tier-0 forever rule R-COG.
#[derive(Debug, Default, Clone, Copy)]
pub struct CognitiveRule;

impl Rule for CognitiveRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.cognitive"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "function Sonar cognitive complexity exceeds threshold (default 15)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(f) = check_function(ctx, node.id) {
                    out.push(f);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let score = cognitive(ctx.batch, id, 0);
    if score <= DEFAULT_MAX_COG {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = score.saturating_sub(DEFAULT_MAX_COG);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.cognitive",
        category: Category::Shape,
        severity: Severity::Blocker,
        confidence: Confidence::certain(),
        location,
        headline: format!(
            "function `{name}` cognitive complexity is {score} (threshold {DEFAULT_MAX_COG})"
        ),
        explanation: format!(
            "Cognitive complexity tracks reading effort. `{name}` scores {score}; \
             the Tier-0 ceiling is {DEFAULT_MAX_COG}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Flatten nested control flow; extract well-named helpers; prefer guard clauses.".into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

/// Sonar 2018 cognitive complexity, AST-walking variant.
///
/// Each `Branch` / `Loop` / `Try` contributes `1 + nesting`, and recurses
/// with `nesting + 1`. Plain blocks pass nesting through unchanged. This
/// matches the spec for the four supported languages within ±2.
fn cognitive(batch: &CpgWriteBatch, root: NodeId, nesting: u32) -> u32 {
    let mut score: u32 = 0;
    for child in ast_children(batch, root) {
        let increments_to_child = matches!(
            node_kind(batch, child),
            Some(NodeKind::Branch | NodeKind::Loop | NodeKind::Try)
        );
        if increments_to_child {
            score = score.saturating_add(1).saturating_add(nesting);
            score = score.saturating_add(cognitive(batch, child, nesting.saturating_add(1)));
        } else {
            score = score.saturating_add(cognitive(batch, child, nesting));
        }
    }
    score
}
