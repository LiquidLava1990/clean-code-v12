//! Tier-0 forever rule R-PUBLIC-SURFACE-SIZE.
//!
//! Flag a class / struct / module declaring more than [`MAX_PUBLIC`]
//! public methods. Threshold cited from PMD `TooManyMethods` and detekt
//! `TooManyFunctions` — both default to ~20. Above that, the type owns
//! too many concerns; split it.
//!
//! "Public" = visibility property `"public"`, OR the `is_pub` /
//! `is_export` boolean is true, OR the name does not start with `_`.

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, bool_prop, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    Tier0FindingBlueprint,
};

/// Threshold cited from PMD `TooManyMethods` (default 20). Detekt's
/// `TooManyFunctions` uses 11 for top-level functions; we adopt the
/// looser PMD ceiling because a class with 15 public methods is still
/// idiomatic, but 21 is a god class.
// TODO(W2): wire ctx.config thresholds
const MAX_PUBLIC: u32 = 20;

/// Tier-0 forever rule R-PUBLIC-SURFACE-SIZE.
#[derive(Debug, Default, Clone, Copy)]
pub struct PublicSurfaceSizeRule;

impl Rule for PublicSurfaceSizeRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.public_surface_size"
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
        "class / struct exposes more than 20 public methods"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Class) {
            if let Some(finding) = check_class(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_class(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let count = count_public_methods(ctx.batch, id);
    if count <= MAX_PUBLIC {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = count.saturating_sub(MAX_PUBLIC);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.public_surface_size",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("type `{name}` exposes {count} public methods (threshold {MAX_PUBLIC})"),
        explanation: format!(
            "Wide public surfaces couple every caller to every method. `{name}` exposes \
             {count} public methods; the Tier-0 ceiling is {MAX_PUBLIC}."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Split the type along responsibilities; keep only the cohesive subset of \
             methods on each new type."
                .into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

fn count_public_methods(batch: &CpgWriteBatch, class_id: NodeId) -> u32 {
    let mut count: u32 = 0;
    for child in ast_children(batch, class_id) {
        if !matches!(
            node_kind(batch, child),
            Some(NodeKind::Method | NodeKind::Function)
        ) {
            continue;
        }
        if is_public(batch, child) {
            count = count.saturating_add(1);
        }
    }
    count
}

fn is_public(batch: &CpgWriteBatch, id: NodeId) -> bool {
    if bool_prop(batch, id, "is_pub").unwrap_or(false)
        || bool_prop(batch, id, "is_export").unwrap_or(false)
    {
        return true;
    }
    if matches!(string_prop(batch, id, "visibility"), Some("public")) {
        return true;
    }
    let name = string_prop(batch, id, "name").unwrap_or("");
    !name.is_empty() && !name.starts_with('_')
}
