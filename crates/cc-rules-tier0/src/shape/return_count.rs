//! Tier-0 forever rule R-RETURN-COUNT.
//!
//! Flag functions whose body contains more than [`MAX_RETURNS`] explicit
//! `return` / `yield` / `throw` nodes at any nesting. PMD
//! `CyclomaticComplexity` lists return-point count as a component;
//! golangci's `nakedret` clamps at 5 by default. We pick 6 for parity
//! with PMD's NPATH/return component and to leave one extra return for
//! a single trailing happy-path expression.
//!
//! Skip rules:
//! - Closures / lambdas (those are scored by `R-LAMBDA-COMPLEXITY`).
//! - Test files (test bodies legitimately fan out across asserts).

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    Tier0FindingBlueprint,
};

/// Threshold chosen for parity with PMD's NPATH/return component
/// (default 6) and golangci `nakedret` (default 5 — we sit one above to
/// allow the trailing happy-path return without flagging).
// TODO(W2): wire ctx.config thresholds
const MAX_RETURNS: u32 = 6;

/// Tier-0 forever rule R-RETURN-COUNT.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReturnCountRule;

impl Rule for ReturnCountRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.return_count"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "function has more than 6 explicit return statements"
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
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let count = count_returns_excluding_nested_fns(ctx.batch, id);
    if count <= MAX_RETURNS {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = count.saturating_sub(MAX_RETURNS);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.return_count",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "function `{name}` has {count} return statements (threshold {MAX_RETURNS})"
        ),
        explanation: format!(
            "Many exit points multiply the paths a reader must trace. `{name}` \
             carries {count} explicit returns; the Tier-0 ceiling is {MAX_RETURNS}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Collapse to a single trailing return; replace early returns with guard \
             clauses that hand off to a helper."
                .into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

/// Count `Return` AST descendants, but stop recursion at any nested
/// `Function` / `Method` boundary so closures don't bleed into the
/// parent count.
fn count_returns_excluding_nested_fns(batch: &CpgWriteBatch, root: NodeId) -> u32 {
    let mut count: u32 = 0;
    for child in ast_children(batch, root) {
        let child_kind = node_kind(batch, child);
        if matches!(child_kind, Some(NodeKind::Function | NodeKind::Method)) {
            // Nested function — its returns belong to it, not to us.
            continue;
        }
        if child_kind == Some(NodeKind::Return) {
            count = count.saturating_add(1);
        }
        count = count.saturating_add(count_returns_excluding_nested_fns(batch, child));
    }
    count
}
