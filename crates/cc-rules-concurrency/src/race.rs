//! `cc.concurrent.race` — shared mutable state without a surrounding lock.
//!
//! Heuristic: scan every async [`NodeKind::Function`] / [`NodeKind::Method`]
//! and every function whose body spawns a thread / task. Inside each
//! such body, look for [`NodeKind::Write`] nodes whose `target` resolves
//! to a top-level (module / class) [`NodeKind::Variable`]. If the
//! enclosing function never acquires a lock (helpers::is_lock_acquire),
//! flag the write as a race.
//!
//! Phase-3 ships heuristic-grade — full lock-region reasoning requires
//! whole-program reachability and is deferred to phase-4.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, collect_descendant_calls, enclosing_file_path, is_async_function,
    is_lock_acquire, is_spawn_call, location_from_node, ConcurrencyFindingBlueprint,
};

/// Family-5 probe R-CONCURRENT-RACE.
///
/// Detects shared mutable state mutated under async / spawn without a
/// surrounding lock. Phase-3 heuristic-grade — see module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct RaceRule;

impl Rule for RaceRule {
    fn rule_id(&self) -> &'static str {
        "cc.concurrent.race"
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
        "shared mutable state mutated without a lock under async / spawn"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for fun in nodes_of_kind(ctx.batch, kind) {
                scan_function(ctx, fun.id, &mut out);
            }
        }
        out
    }
}

/// Inspect one function body — emit a finding per unguarded shared write.
fn scan_function(ctx: &RuleContext<'_>, fun: NodeId, out: &mut Vec<Finding>) {
    let mut calls: Vec<NodeId> = Vec::new();
    collect_descendant_calls(ctx.batch, fun, &mut calls);
    let async_fn = is_async_function(ctx.batch, fun);
    let spawns = calls
        .iter()
        .any(|c| is_spawn_call(&callee_text(ctx.batch, *c)));
    if !async_fn && !spawns {
        return;
    }
    if calls
        .iter()
        .any(|c| is_lock_acquire(&callee_text(ctx.batch, *c)))
    {
        return;
    }
    for write in writes_under(ctx, fun) {
        if let Some(finding) = emit_for_write(ctx, fun, write) {
            out.push(finding);
        }
    }
}

/// Collect every [`NodeKind::Write`] that descends transitively from
/// `root` without crossing another function boundary.
fn writes_under(ctx: &RuleContext<'_>, root: NodeId) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut stack: Vec<NodeId> = cc_frontend::query::ast_children(ctx.batch, root).collect();
    while let Some(id) = stack.pop() {
        let kind = node_kind(ctx.batch, id);
        if matches!(kind, Some(NodeKind::Function | NodeKind::Method)) {
            continue;
        }
        for child in cc_frontend::query::ast_children(ctx.batch, id) {
            stack.push(child);
        }
        if kind == Some(NodeKind::Write) {
            out.push(id);
        }
    }
    out
}

/// Emit one finding for a Write whose `target` resolves to a top-level
/// Variable (module / class field). Returns `None` for local-scope writes.
fn emit_for_write(ctx: &RuleContext<'_>, fun: NodeId, write: NodeId) -> Option<Finding> {
    let target = string_prop(ctx.batch, write, "target")?;
    if !target_is_top_level(ctx, target) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, fun)?;
    let location = location_from_node(ctx.batch, write, path);
    Some(build_finding(ConcurrencyFindingBlueprint {
        rule_id: "cc.concurrent.race",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("shared mutable `{target}` written without a lock"),
        explanation: format!(
            "`{target}` is module / class scope and the enclosing function \
             runs concurrently (async / spawned). Without a `Mutex`, \
             `RwLock`, or equivalent guard, two tasks can interleave and \
             corrupt the value."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the shared state in `Arc<Mutex<...>>` (Rust), \
             `asyncio.Lock` (Python), `sync.Mutex` (Go), or move the \
             state into the task that owns it and pass updates through \
             a channel."
                .into(),
        ),
        snippet: target.to_owned(),
        weight: 5,
    }))
}

/// True iff the named identifier resolves to a top-level Variable
/// (parent is File / Module / Class).
fn target_is_top_level(ctx: &RuleContext<'_>, name: &str) -> bool {
    nodes_of_kind(ctx.batch, NodeKind::Variable).any(|v| {
        if string_prop(ctx.batch, v.id, "name") != Some(name) {
            return false;
        }
        matches!(
            ast_parent(ctx.batch, v.id).and_then(|p| node_kind(ctx.batch, p)),
            Some(NodeKind::File | NodeKind::Module | NodeKind::Class)
        )
    })
}
