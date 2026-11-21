//! `cc.perf.alloc_in_loop` — heap-allocating constructor in a loop body.
//!
//! Algorithm: every [`NodeKind::Call`] inside a [`NodeKind::Loop`] body
//! whose callee text matches one of the canonical allocator constructors
//! (`Vec::new`, `HashMap::new`, `Box::new`, `dict()`, `make([]T,…)`, …)
//! is reported. Allocation in the loop body is almost always a sign that
//! the binding could be hoisted + reused.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_inside_loop, location_from_node,
    PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-ALLOC-IN-LOOP.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllocInLoopRule;

/// Canonical allocator constructors. Substring match against the callee
/// text — covers Rust (`Vec::new`, `Box::new`), Python (`dict()`,
/// `list()`), Go (`make([]T,`), and JS (`new Map`, `new Set`).
const ALLOCATORS: &[&str] = &[
    "Vec::new",
    "vec![",
    "HashMap::new",
    "BTreeMap::new",
    "HashSet::new",
    "BTreeSet::new",
    "Box::new",
    "String::new",
    "Map(",
    "new Map",
    "new Set",
    "dict(",
    "list(",
    "set(",
    "make([",
];

impl Rule for AllocInLoopRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.alloc_in_loop"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        // The "binding referenced only in same loop" heuristic the spec
        // calls for needs PDG_DATA edges that current frontends don't
        // emit reliably; we down-weight confidence to match the looser
        // detection. TODO(phase-3): tighten via PDG_DATA reachability.
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "heap allocator called inside a loop body"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            let text = callee_text(ctx.batch, node.id);
            let Some(hit) = ALLOCATORS.iter().find(|needle| text.contains(*needle)) else {
                continue;
            };
            if !is_inside_loop(ctx.batch, node.id) {
                continue;
            }
            if let Some(finding) = emit(ctx, node.id, hit) {
                out.push(finding);
            }
        }
        out
    }
}

fn emit(ctx: &RuleContext<'_>, call: NodeId, allocator: &str) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call)?;
    let location = location_from_node(ctx.batch, call, path);
    Some(build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.alloc_in_loop",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{allocator}` allocates on every loop iteration"),
        explanation: format!(
            "`{allocator}` allocates on the heap; placing it inside a loop \
             body multiplies the allocator pressure by the iteration count. \
             Hoist the binding above the loop and reuse it (`clear()` between \
             iterations) when the value's lifetime allows."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Hoist the allocation above the loop and reset the buffer between \
             iterations, or pre-size with `with_capacity` if the count is known."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}
