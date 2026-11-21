//! `cc.concurrent.lock_inversion` — inconsistent lock acquisition order
//! between two functions sharing overlapping locks (deadlock cycle risk).
//!
//! Heuristic: build a per-function "lock order" — the encounter sequence
//! of lock-acquire callee texts inside the function body. For every pair
//! of functions that share at least two locks, check whether their
//! relative orders agree. A disagreement is reported on both functions.
//!
//! Phase-3 ships heuristic-grade. Cross-function reasoning is bounded
//! to in-batch functions. TODO(phase-4): extend across compilation units
//! once the persistent CPG store is wired.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, collect_descendant_calls, enclosing_file_path, is_lock_acquire,
    location_from_node, ConcurrencyFindingBlueprint,
};

/// Family-5 probe R-CONCURRENT-LOCK-INVERSION.
#[derive(Debug, Default, Clone, Copy)]
pub struct LockInversionRule;

impl Rule for LockInversionRule {
    fn rule_id(&self) -> &'static str {
        "cc.concurrent.lock_inversion"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Concurrent
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "two functions acquire overlapping locks in different orders"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let orders = collect_lock_orders(ctx);
        let conflicts = find_conflicts(&orders);
        let mut out = Vec::new();
        for (idx, _other_idx) in conflicts {
            if let Some(finding) = emit_for_function(ctx, &orders[idx]) {
                out.push(finding);
            }
        }
        out
    }
}

/// One function's recorded lock-acquire order.
struct LockOrder {
    function: NodeId,
    name: String,
    locks: Vec<String>,
}

/// Walk every function / method and capture the in-order list of
/// lock-acquire callees. Functions with fewer than two locks are kept —
/// pair comparison filters them out.
fn collect_lock_orders(ctx: &RuleContext<'_>) -> Vec<LockOrder> {
    let mut out = Vec::new();
    for kind in [NodeKind::Function, NodeKind::Method] {
        for fun in nodes_of_kind(ctx.batch, kind) {
            let mut calls: Vec<NodeId> = Vec::new();
            collect_descendant_calls(ctx.batch, fun.id, &mut calls);
            let locks: Vec<String> = calls
                .into_iter()
                .map(|c| callee_text(ctx.batch, c))
                .filter(|t| is_lock_acquire(t))
                .collect();
            if locks.is_empty() {
                continue;
            }
            let name = string_prop(ctx.batch, fun.id, "name")
                .unwrap_or("<anon>")
                .to_owned();
            out.push(LockOrder {
                function: fun.id,
                name,
                locks,
            });
        }
    }
    out
}

/// For every pair of orders, return `(i, j)` when they share two locks
/// in opposite relative order. Each disagreeing function is reported.
fn find_conflicts(orders: &[LockOrder]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..orders.len() {
        for j in (i + 1)..orders.len() {
            if pairs_disagree(&orders[i].locks, &orders[j].locks) {
                out.push((i, j));
                out.push((j, i));
            }
        }
    }
    out
}

/// True iff `a` and `b` contain two locks `x`, `y` with `x` before `y`
/// in `a` and `y` before `x` in `b`.
fn pairs_disagree(a: &[String], b: &[String]) -> bool {
    for (xa, x) in a.iter().enumerate() {
        for y in a.iter().skip(xa + 1) {
            if pair_inverted(b, x, y) {
                return true;
            }
        }
    }
    false
}

/// True iff `b` contains both `x` and `y` and orders them as `y` before `x`.
fn pair_inverted(b: &[String], x: &str, y: &str) -> bool {
    let (Some(xb), Some(yb)) = (find_index(b, x), find_index(b, y)) else {
        return false;
    };
    xb > yb
}

fn find_index(haystack: &[String], needle: &str) -> Option<usize> {
    haystack.iter().position(|s| s == needle)
}

fn emit_for_function(ctx: &RuleContext<'_>, order: &LockOrder) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, order.function)?;
    let location = location_from_node(ctx.batch, order.function, path);
    let preview = order.locks.join(" -> ");
    Some(build_finding(ConcurrencyFindingBlueprint {
        rule_id: "cc.concurrent.lock_inversion",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.7),
        location,
        headline: format!(
            "`{}` acquires locks in conflicting order ({preview})",
            order.name
        ),
        explanation: format!(
            "Function `{}` acquires multiple locks; another function in \
             this batch acquires an overlapping pair in the opposite order. \
             Two threads can each hold one lock and wait forever on the other.",
            order.name
        ),
        remediation: Remediation::SuggestedRewrite(
            "Pick a single global lock-acquire order (e.g. by stable address \
             or a documented hierarchy) and apply it everywhere. Or merge the \
             two locks into one if the resources are inseparable."
                .into(),
        ),
        snippet: preview,
        weight: 5,
    }))
}
