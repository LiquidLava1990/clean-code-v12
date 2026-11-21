//! Tier-0 forever rule R-STATEMENT-COUNT.
//!
//! Flag a function whose body has more than [`MAX_STATEMENTS`] top-level
//! statements (statement-shaped AST nodes whose AST parent is the
//! function itself or its top-level block). Threshold cited from Ruff
//! `PLR0915 too-many-statements` (default 50). Mirrors the per-function
//! LOC ceiling in spirit but counts AST nodes, not lines, so a 60-line
//! function of three big expressions stays clean while a 30-line
//! function of 60 chained writes fires.

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    Tier0FindingBlueprint,
};

/// Threshold cited from Ruff `PLR0915 too-many-statements` (default 50).
// TODO(W2): wire ctx.config thresholds
const MAX_STATEMENTS: u32 = 50;

/// Statement-shaped AST kinds. `Block` is unwrapped one level to reach
/// the real body when frontends wrap the function body in a single
/// `Block` child.
fn is_statement_kind(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Variable
            | NodeKind::Branch
            | NodeKind::Loop
            | NodeKind::Try
            | NodeKind::Return
            | NodeKind::Call
            | NodeKind::Write
            | NodeKind::Read
            | NodeKind::Async
            | NodeKind::Event
    )
}

/// Tier-0 forever rule R-STATEMENT-COUNT.
#[derive(Debug, Default, Clone, Copy)]
pub struct StatementCountRule;

impl Rule for StatementCountRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.statement_count"
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
        "function body has more than 50 top-level statements"
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
    let count = count_top_level_statements(ctx.batch, id);
    if count <= MAX_STATEMENTS {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = count.saturating_sub(MAX_STATEMENTS);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.statement_count",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "function `{name}` has {count} top-level statements (threshold {MAX_STATEMENTS})"
        ),
        explanation: format!(
            "Long statement lists hide responsibilities. `{name}` runs {count} \
             top-level statements; the Tier-0 ceiling is {MAX_STATEMENTS}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Extract sub-functions, each owning one logical step; aim well below 50.".into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

/// Count statement-shaped children of `fn_id`. Unwraps a single `Block`
/// child one level (Rust/TS frontends wrap the body in a Block).
fn count_top_level_statements(batch: &CpgWriteBatch, fn_id: NodeId) -> u32 {
    let body_root = unwrap_single_block(batch, fn_id);
    let mut count: u32 = 0;
    for child in ast_children(batch, body_root) {
        if let Some(kind) = node_kind(batch, child) {
            if is_statement_kind(kind) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

fn unwrap_single_block(batch: &CpgWriteBatch, fn_id: NodeId) -> NodeId {
    let children: Vec<NodeId> = ast_children(batch, fn_id)
        .filter(|c| {
            !matches!(
                node_kind(batch, *c),
                Some(NodeKind::Parameter | NodeKind::Decorator | NodeKind::Type)
            )
        })
        .collect();
    if children.len() == 1 && node_kind(batch, children[0]) == Some(NodeKind::Block) {
        return children[0];
    }
    fn_id
}
