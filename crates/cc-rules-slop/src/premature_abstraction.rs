//! `cc.slop.premature_abstraction` — flag interfaces / traits / ABCs
//! with exactly one implementation, or helpers called from exactly one
//! site.
//!
//! Phase-2 detectors:
//!
//! 1. A `Class` whose `kind` property is `iface` (Rust trait) or whose
//!    `lang_ext.is_interface` is `true` (TS interface). We count
//!    incoming `CG_OVERRIDES` edges; when there is exactly one, the
//!    abstraction is premature.
//! 2. A function whose name matches the helper suffix pattern AND has
//!    exactly one incoming `CG_CALLS` edge — a single-caller helper is
//!    almost always inlinable.
//!
//! The probe is silent when the lifted batch lacks call-graph signal,
//! same gating as `cc.slop.unused_helper`.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeId, NodeKind, Value};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{incoming_edges_of_kind, node_by_id, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_fake_thoughtful_suffix, location_from_node,
    SlopFindingBlueprint,
};

/// Family-1 rule R-SLOP-PREMATURE.
#[derive(Debug, Default, Clone, Copy)]
pub struct PrematureAbstractionRule;

impl Rule for PrematureAbstractionRule {
    fn rule_id(&self) -> &'static str {
        "cc.slop.premature_abstraction"
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
        "single-impl interface or single-caller helper"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        if !batch_has_call_resolution(ctx.batch) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for class in nodes_of_kind(ctx.batch, NodeKind::Class) {
            if let Some(f) = check_iface_single_impl(ctx, class.id) {
                out.push(f);
            }
        }
        for kind in [NodeKind::Function, NodeKind::Method] {
            for func in nodes_of_kind(ctx.batch, kind) {
                if let Some(f) = check_fn_single_caller(ctx, func.id) {
                    out.push(f);
                }
            }
        }
        out
    }
}

fn batch_has_call_resolution(batch: &CpgWriteBatch) -> bool {
    batch.edges().iter().any(|e| {
        matches!(
            e.kind,
            EdgeKind::CG_CALLS | EdgeKind::REFERENCES | EdgeKind::CG_OVERRIDES
        )
    })
}

/// True iff `id` has exactly one incoming edge of kind `edge_kind` —
/// the canonical "single producer / single caller" signal both detectors
/// share.
fn has_single_incoming_edge(batch: &CpgWriteBatch, id: NodeId, edge_kind: EdgeKind) -> bool {
    incoming_edges_of_kind(batch, id, edge_kind).count() == 1
}

/// Build a `cc.slop.premature_abstraction` finding with the standard
/// severity/confidence stamping. Every detector funnels through this so
/// the blueprint boilerplate is written exactly once.
fn build_premature_abstraction(
    ctx: &RuleContext<'_>,
    id: NodeId,
    headline: String,
    explanation: String,
    rewrite: String,
) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(SlopFindingBlueprint {
        rule_id: "cc.slop.premature_abstraction",
        category: Category::Slop,
        severity: Severity::Required,
        confidence: Confidence::new(0.88),
        location,
        headline,
        explanation,
        remediation: Remediation::SuggestedRewrite(rewrite),
        snippet: String::new(),
        weight: 1,
    }))
}

fn check_iface_single_impl(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    if !is_interface_like(ctx.batch, id) {
        return None;
    }
    if !has_single_incoming_edge(ctx.batch, id, EdgeKind::CG_OVERRIDES) {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    build_premature_abstraction(
        ctx,
        id,
        format!("interface `{name}` has exactly one implementation"),
        format!(
            "Interface / trait `{name}` is implemented exactly once. \
             Single-impl abstractions add a name layer with no \
             polymorphism payoff — collapse them until a real second \
             implementation appears."
        ),
        format!(
            "Inline the lone implementation back into its callers, or \
             delete `{name}` and use the concrete type directly."
        ),
    )
}

fn check_fn_single_caller(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    if !is_fake_thoughtful_suffix(name) {
        return None;
    }
    if !has_single_incoming_edge(ctx.batch, id, EdgeKind::CG_CALLS) {
        return None;
    }
    build_premature_abstraction(
        ctx,
        id,
        format!("helper `{name}` has exactly one caller"),
        format!(
            "Helper-named function `{name}` is called from exactly one \
             site. Single-caller helpers add an indirection without \
             reusing the abstraction — inline them."
        ),
        format!(
            "Inline `{name}` at its single call site. If the helper exists \
             to clarify intent, lift the body's logic into a comment block \
             and remove the wrapping function."
        ),
    )
}

/// True iff the Class node is interface-like:
///
/// - Rust: `kind` prop equals `"iface"` (set by the Rust frontend on
///   `trait_item`).
/// - TypeScript: `lang_ext.is_interface` is `true`.
fn is_interface_like(batch: &CpgWriteBatch, id: NodeId) -> bool {
    if let Some(kind) = string_prop(batch, id, "kind") {
        if kind == "iface" {
            return true;
        }
    }
    let Some(node) = node_by_id(batch, id) else {
        return false;
    };
    let Some(Value::Map(lang_ext)) = node.prop("lang_ext") else {
        return false;
    };
    matches!(lang_ext.get("is_interface"), Some(Value::Bool(true)))
}
