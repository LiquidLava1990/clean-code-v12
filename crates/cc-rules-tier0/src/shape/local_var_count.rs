//! Tier-0 forever rule R-LOCAL-VAR-COUNT.
//!
//! Flag a function declaring more than `MAX_LOCALS` distinct local
//! variables. Threshold cited from Ruff `PLR0914 too-many-locals`
//! (default 15). Above that, a function is bookkeeping its own
//! intermediate state — extract a struct or split the function.

use std::collections::HashSet;

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    Tier0FindingBlueprint,
};

/// Threshold cited from Ruff `PLR0914 too-many-locals` (default 15).
// TODO(W2): wire ctx.config thresholds
const MAX_LOCALS: u32 = 15;

/// Tier-0 forever rule R-LOCAL-VAR-COUNT.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalVarCountRule;

impl Rule for LocalVarCountRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.local_var_count"
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
        "function declares more than 15 distinct local variables"
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
    let count = count_distinct_locals(ctx.batch, id);
    if count <= MAX_LOCALS {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = count.saturating_sub(MAX_LOCALS);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.local_var_count",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "function `{name}` declares {count} local variables (threshold {MAX_LOCALS})"
        ),
        explanation: format!(
            "Many locals signal a function bookkeeping its own intermediate state. \
             `{name}` carries {count} distinct locals; the Tier-0 ceiling is {MAX_LOCALS}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Group related locals into a struct / dataclass; extract sub-functions \
             that each own a smaller slice of state."
                .into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

/// Walk the AST descendants of `root` and count distinct
/// `Variable`-kind names. Stop recursion at any nested `Function` /
/// `Method` boundary so closures don't bleed into the parent count.
fn count_distinct_locals(batch: &CpgWriteBatch, root: NodeId) -> u32 {
    let mut seen: HashSet<String> = HashSet::new();
    walk_locals(batch, root, &mut seen);
    u32::try_from(seen.len()).unwrap_or(u32::MAX)
}

fn walk_locals(batch: &CpgWriteBatch, root: NodeId, seen: &mut HashSet<String>) {
    for child in ast_children(batch, root) {
        let kind = node_kind(batch, child);
        if matches!(kind, Some(NodeKind::Function | NodeKind::Method)) {
            continue;
        }
        if kind == Some(NodeKind::Variable) {
            if let Some(name) = string_prop(batch, child, "name") {
                seen.insert(name.to_owned());
            }
        }
        walk_locals(batch, child, seen);
    }
}
