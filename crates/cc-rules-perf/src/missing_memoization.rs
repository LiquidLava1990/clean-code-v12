//! `cc.perf.missing_memoization` — pure helper called > 3 times from one
//! caller body.
//!
//! Algorithm: walk every [`cc_cpg::EdgeKind::CG_CALLS`] edge, group by
//! `(caller, callee)`, and emit a finding when (a) the same caller calls
//! the same callee more than three times, and (b) the callee's name
//! contains no I/O signal words (`read`, `write`, `fetch`, `query`,
//! `send`, `recv`). The rule needs CG_CALLS edges to fire — the same
//! gating pattern used by `cc.shape.dead_code` keeps it silent when the
//! frontend hasn't emitted them.

use std::collections::BTreeMap;

use cc_cpg::{EdgeKind, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{node_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, enclosing_function, location_from_node,
    PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-MISSING-MEMOIZATION.
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingMemoizationRule;

/// Minimum repeat-call count from a single caller before we suggest
/// memoisation.
const REPEAT_THRESHOLD: usize = 3;

/// Substrings that indicate the callee performs I/O — memoisation would
/// hide stale results, so we exempt these.
const IO_SIGNAL_WORDS: &[&str] = &["read", "write", "fetch", "query", "send", "recv"];

impl Rule for MissingMemoizationRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.missing_memoization"
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
        "pure helper called > 3 times from one caller — memoise"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        if !batch_has_call_resolution(ctx) {
            return Vec::new();
        }
        let counts = aggregate_call_counts(ctx);
        let mut out = Vec::new();
        for ((_caller, callee), count) in counts {
            if count <= REPEAT_THRESHOLD {
                continue;
            }
            if callee_is_io(ctx, callee) {
                continue;
            }
            if let Some(finding) = emit(ctx, callee, count) {
                out.push(finding);
            }
        }
        out
    }
}

/// Aggregate `(caller_function, callee)` -> count from CG_CALLS edges.
fn aggregate_call_counts(ctx: &RuleContext<'_>) -> BTreeMap<(NodeId, NodeId), usize> {
    let mut counts: BTreeMap<(NodeId, NodeId), usize> = BTreeMap::new();
    for edge in ctx.batch.edges() {
        if edge.kind != EdgeKind::CG_CALLS {
            continue;
        }
        // Edge `from` is the Call site; resolve to its enclosing function.
        let Some(caller_fn) = enclosing_function(ctx.batch, edge.from) else {
            continue;
        };
        if !matches!(
            node_kind(ctx.batch, edge.to),
            Some(NodeKind::Function | NodeKind::Method)
        ) {
            continue;
        }
        *counts.entry((caller_fn, edge.to)).or_insert(0) += 1;
    }
    counts
}

/// True iff the batch carries any CG_CALLS edge — the minimum signal the
/// rule needs.
fn batch_has_call_resolution(ctx: &RuleContext<'_>) -> bool {
    ctx.batch
        .edges()
        .iter()
        .any(|e| e.kind == EdgeKind::CG_CALLS)
}

/// True iff the callee's name contains an I/O signal word.
fn callee_is_io(ctx: &RuleContext<'_>, callee: NodeId) -> bool {
    let Some(name) = string_prop(ctx.batch, callee, "name") else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    IO_SIGNAL_WORDS.iter().any(|word| lower.contains(*word))
}

fn emit(ctx: &RuleContext<'_>, callee: NodeId, count: usize) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, callee)?;
    let name = string_prop(ctx.batch, callee, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, callee, path);
    Some(build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.missing_memoization",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{name}` called {count}× from one caller — memoise"),
        explanation: format!(
            "`{name}` is invoked {count} times from a single caller body and \
             its name shows no I/O signal — the result is almost certainly a \
             pure function of its arguments. Cache the result in a local \
             variable, or decorate with `@functools.lru_cache` / `once_cell` \
             so repeated calls collapse to one."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Hoist the call into a single binding, or memoise via \
             `functools.lru_cache` / `once_cell::Lazy` so the body runs once."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}
