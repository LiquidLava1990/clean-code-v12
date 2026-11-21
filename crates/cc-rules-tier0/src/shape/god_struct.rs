//! Tier-0 forever rule R-GOD-STRUCT.
//!
//! Flag a class / struct that exceeds BOTH [`MAX_FIELDS`] AND
//! [`MAX_METHODS`]. The conjunction is deliberate (per OSS source PMD
//! `GodClass` + detekt `LargeClass`):
//!
//! - Large data classes (many fields, few methods) get a pass.
//! - Large service classes (few fields, many methods) get a pass on
//!   field count — they're already covered by R-PUBLIC-SURFACE-SIZE.
//! - Only the union — wide AND tall — qualifies as a "god struct".
//!
//! Thresholds cited from PMD `GodClass` (12 fields) and detekt
//! `LargeClass` (15 methods).

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    Tier0FindingBlueprint,
};

/// Threshold cited from PMD `GodClass` (default 12 fields).
// TODO(W2): wire ctx.config thresholds
const MAX_FIELDS: u32 = 12;

/// Threshold cited from detekt `LargeClass` (default 15 methods).
// TODO(W2): wire ctx.config thresholds
const MAX_METHODS: u32 = 15;

/// Tier-0 forever rule R-GOD-STRUCT.
#[derive(Debug, Default, Clone, Copy)]
pub struct GodStructRule;

impl Rule for GodStructRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.god_struct"
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
        "class / struct has more than 12 fields AND more than 15 methods"
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
    let (fields, methods) = count_members(ctx.batch, id);
    if fields <= MAX_FIELDS || methods <= MAX_METHODS {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let weight = fields
        .saturating_sub(MAX_FIELDS)
        .saturating_add(methods.saturating_sub(MAX_METHODS));
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.god_struct",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "type `{name}` is a god struct ({fields} fields, {methods} methods; thresholds {MAX_FIELDS}/{MAX_METHODS})"
        ),
        explanation: format!(
            "God structs hide multiple responsibilities behind one name. `{name}` carries \
             {fields} fields and {methods} methods, both above the Tier-0 ceilings of \
             {MAX_FIELDS} and {MAX_METHODS}. Either count alone would be acceptable; \
             the union is not."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Split into smaller cohesive types: identify clusters of fields used together \
             by overlapping method sets; extract each cluster into its own type."
                .into(),
        ),
        snippet: String::new(),
        weight,
    }))
}

/// Count `(fields, methods)` of `class_id`. Fields = `Variable` /
/// `Parameter`-kind direct children (frontends differ); methods =
/// `Method` / `Function` direct children.
fn count_members(batch: &CpgWriteBatch, class_id: NodeId) -> (u32, u32) {
    let mut fields: u32 = 0;
    let mut methods: u32 = 0;
    for child in ast_children(batch, class_id) {
        match node_kind(batch, child) {
            Some(NodeKind::Variable) => fields = fields.saturating_add(1),
            Some(NodeKind::Method | NodeKind::Function) => {
                methods = methods.saturating_add(1);
            }
            _ => {}
        }
    }
    (fields, methods)
}
