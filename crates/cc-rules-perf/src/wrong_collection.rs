//! `cc.perf.wrong_collection` — membership lookup against a long array.
//!
//! Algorithm: every [`NodeKind::Call`] whose callee text reads as a
//! membership operator (`in`, `.contains`, `.includes`) is inspected. If
//! the receiver is a Variable / Read / Identifier carrying an
//! `element_count` integer prop > 3 (or whose name suggests a list and
//! whose `is_array_literal` bool is set), we report it.
//!
//! Phase-1 stub: most frontends do not yet emit `element_count` on array
//! literals, so detection is gated on that prop. When the prop is
//! missing the rule stays silent rather than guessing — silent under-fire
//! is the explicit Phase-1 contract.
//!
//! TODO(phase-3): wire `element_count` from the four frontends and
//! relax the gate.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, int_prop, node_kind, nodes_of_kind};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, location_from_node, PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-WRONG-COLLECTION.
#[derive(Debug, Default, Clone, Copy)]
pub struct WrongCollectionRule;

/// Membership-operator markers visible in `callee_text`.
const MEMBERSHIP_HINTS: &[&str] = &[" in ", ".contains", ".includes"];

/// Threshold above which a linear membership scan is wasteful relative to
/// a hash-set lookup.
const ELEMENT_COUNT_THRESHOLD: i64 = 3;

impl Rule for WrongCollectionRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.wrong_collection"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "membership lookup against a long array literal — use a set"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            let text = callee_text(ctx.batch, node.id);
            if !MEMBERSHIP_HINTS.iter().any(|needle| text.contains(*needle)) {
                continue;
            }
            if !arg_is_long_literal(ctx, node.id) {
                continue;
            }
            if let Some(finding) = emit(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

/// True iff any argument carries an `element_count` int prop greater
/// than the threshold.
fn arg_is_long_literal(ctx: &RuleContext<'_>, call: NodeId) -> bool {
    for child in ast_children(ctx.batch, call) {
        if !matches!(
            node_kind(ctx.batch, child),
            Some(NodeKind::Variable | NodeKind::Read | NodeKind::Identifier | NodeKind::Literal)
        ) {
            continue;
        }
        if int_prop(ctx.batch, child, "element_count")
            .is_some_and(|count| count > ELEMENT_COUNT_THRESHOLD)
        {
            return true;
        }
    }
    false
}

fn emit(ctx: &RuleContext<'_>, call: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call)?;
    let location = location_from_node(ctx.batch, call, path);
    Some(build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.wrong_collection",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "membership lookup against a long list literal".into(),
        explanation: format!(
            "Linear scan over a list with > {ELEMENT_COUNT_THRESHOLD} elements \
             is O(N) per lookup. Convert the literal to a hash-backed set / \
             frozenset / `HashSet<&str>` once, then test membership in O(1)."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Promote the literal to a module-level set / frozenset and test \
             membership against that constant; the lookup drops from O(N) to \
             O(1)."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}
