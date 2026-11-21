//! `cc.shape.dead_code` — flag top-level Functions / Classes that have
//! no incoming `REFERENCES` or `CG_CALLS` edge.
//!
//! Phase-1 conservatism: only top-level (parent is File or Module)
//! symbols are reported; local-scope dead code is too noisy. Skips
//! `main`, dunders (`__init__`, …), test functions (`test_*`), and any
//! symbol whose `visibility == "public"` or `is_export == true`.

use cc_cpg::{CpgWriteBatch, EdgeKind, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{
    ast_parent, bool_prop, incoming_edges_of_kind, node_kind, nodes_of_kind, string_prop,
};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    Tier0FindingBlueprint,
};

/// Tier-0 forever rule R-DEAD.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeadCodeRule;

impl Rule for DeadCodeRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.dead_code"
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
        "top-level symbol has no incoming references"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        if !batch_has_call_resolution(ctx.batch) {
            // The frontend that produced this batch has not emitted any
            // CG_CALLS / REFERENCES / CG_OVERRIDES edges, so we have no
            // signal — every symbol would look "dead" by accident. Skip
            // silently rather than mass-flag false positives.
            return Vec::new();
        }
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method, NodeKind::Class] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_symbol(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

/// True iff the batch carries at least one call-graph or reference edge —
/// the minimum signal the rule needs to distinguish dead from live.
fn batch_has_call_resolution(batch: &CpgWriteBatch) -> bool {
    batch.edges().iter().any(|e| {
        matches!(
            e.kind,
            EdgeKind::CG_CALLS | EdgeKind::REFERENCES | EdgeKind::CG_OVERRIDES
        )
    })
}

fn check_symbol(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    if !is_top_level(ctx, id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id);
    if path.as_ref().is_some_and(is_test_file_path) {
        // Test files contain `#[test]` / `test_*` entry points called only
        // by the test runner, not by surrounding source. Per-batch dead-code
        // analysis can't see the runner; flagging them is mass FP.
        return None;
    }
    if is_exempt(ctx, id) {
        return None;
    }
    if has_any_incoming(ctx, id) {
        return None;
    }
    let path = path?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let kind_label = match node_kind(ctx.batch, id) {
        Some(NodeKind::Class) => "class",
        Some(NodeKind::Method) => "method",
        _ => "function",
    };
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.dead_code",
        category: Category::Slop,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("{kind_label} `{name}` has no incoming references"),
        explanation: format!(
            "Dead code rots. {kind_label} `{name}` is defined at top level but \
             nothing in this batch references it; if it is unused, delete it."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Delete the symbol if truly unused, or wire it into the call graph; \
             if the symbol is intentionally part of a public API, mark it `pub` / \
             `export` so the rule recognises it as live."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}

fn is_top_level(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    matches!(
        ast_parent(ctx.batch, id).and_then(|p| node_kind(ctx.batch, p)),
        Some(NodeKind::File | NodeKind::Module)
    )
}

fn is_exempt(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    if bool_prop(ctx.batch, id, "is_pub").unwrap_or(false)
        || bool_prop(ctx.batch, id, "is_export").unwrap_or(false)
    {
        return true;
    }
    if matches!(string_prop(ctx.batch, id, "visibility"), Some("public")) {
        return true;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("");
    is_exempt_name(name)
}

fn is_exempt_name(name: &str) -> bool {
    matches!(name, "main" | "init")
        || name.starts_with("__")
        || name.starts_with("test_")
        || name.ends_with("_test")
}

fn has_any_incoming(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let any_ref = incoming_edges_of_kind(ctx.batch, id, cc_cpg::EdgeKind::REFERENCES)
        .next()
        .is_some();
    let any_call = incoming_edges_of_kind(ctx.batch, id, cc_cpg::EdgeKind::CG_CALLS)
        .next()
        .is_some();
    let any_override = incoming_edges_of_kind(ctx.batch, id, cc_cpg::EdgeKind::CG_OVERRIDES)
        .next()
        .is_some();
    any_ref || any_call || any_override
}
