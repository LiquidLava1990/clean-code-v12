//! `cc.shape.nesting_depth` — flag functions whose AST nesting exceeds
//! the per-repo threshold (default 3).

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, snippet_from_bytes,
    Tier0FindingBlueprint,
};

/// Phase-1 default threshold per `docs/design/TIER_0_ALGORITHMS.md`.
// TODO(W2): wire ctx.config thresholds
const DEFAULT_MAX_DEPTH: u32 = 3;

/// Tier-0 forever rule R-NEST.
#[derive(Debug, Default, Clone, Copy)]
pub struct NestingDepthRule;

impl Rule for NestingDepthRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.nesting_depth"
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
        "function AST nesting exceeds threshold (default 3)"
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
    let depth = max_nesting_depth(ctx.batch, id, 0);
    if depth <= DEFAULT_MAX_DEPTH {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let weight = (depth - DEFAULT_MAX_DEPTH).saturating_mul(3);
    let location = location_from_node(ctx.batch, id, path.clone());
    let bytes = ctx.source.get(path.as_path());
    let snippet = cc_frontend::query::range_prop(ctx.batch, id, "range")
        .map(|r| snippet_from_bytes(bytes, r.start.offset, r.end.offset))
        .unwrap_or_default();
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.nesting_depth",
        category: Category::Shape,
        severity: Severity::Blocker,
        confidence: Confidence::certain(),
        location,
        headline: format!("function `{name}` nests {depth} deep (threshold {DEFAULT_MAX_DEPTH})"),
        explanation: format!(
            "Deep nesting hides control flow. Function `{name}` reaches depth \
             {depth}; the Tier-0 ceiling is {DEFAULT_MAX_DEPTH}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Use early returns, guard clauses, and helper extraction to keep depth <= 3.".into(),
        ),
        snippet,
        weight,
    }))
}

/// Walk descendants via AST_PARENT (incoming edges). Returns the deepest
/// nesting count seen, where each `Branch` / `Loop` / `Try` adds 1.
fn max_nesting_depth(batch: &CpgWriteBatch, root: NodeId, depth: u32) -> u32 {
    let mut max_seen = depth;
    for child in ast_children(batch, root) {
        let kind = node_kind(batch, child);
        let next_depth = if matches!(
            kind,
            Some(NodeKind::Branch | NodeKind::Loop | NodeKind::Try)
        ) {
            depth.saturating_add(1)
        } else {
            depth
        };
        let child_depth = max_nesting_depth(batch, child, next_depth);
        if child_depth > max_seen {
            max_seen = child_depth;
        }
    }
    max_seen
}
