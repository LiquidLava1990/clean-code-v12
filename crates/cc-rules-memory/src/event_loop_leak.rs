//! `cc.memory.event_loop_leak` — refs preventing event-loop GC.
//!
//! Heuristic: in any [`NodeKind::Function`] / [`NodeKind::Method`] whose
//! `is_async` property is true (or whose name carries an `async`-style
//! marker), find [`NodeKind::Write`] nodes whose `initializer` is a
//! spawn / timer / interval call:
//!
//! - `tokio::spawn` / `tokio::task::spawn`
//! - `asyncio.create_task` / `loop.create_task`
//! - `setInterval` / `setTimeout`
//! - `std::thread::spawn` (kept under the leak banner — handle leak)
//!
//! For each spawn-result write we ask: does the bound `target` appear
//! as a receiver in any subsequent Call inside the same function whose
//! method is `await` / `cancel` / `abort` / `clear` /
//! `clearInterval` / `clearTimeout`? If not, the handle is leaked into
//! the event loop and the rule fires.
//!
//! Conservative skip: if the write is inside a `Try` ancestor we still
//! flag — try-with-resources doesn't apply to spawn handles. Test files
//! and rule-pack source are skipped to keep self-host clean.

use cc_cpg::{CpgWriteBatch, Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, bool_prop, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, enclosing_function, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, MemoryFindingBlueprint,
};

/// Family-6 probe R-MEM-EVTLOOP.
#[derive(Debug, Default, Clone, Copy)]
pub struct EventLoopLeakRule;

const SPAWN_PRODUCERS: &[&str] = &[
    "tokio::spawn",
    "tokio::task::spawn",
    "asyncio.create_task",
    "loop.create_task",
    "ensure_future",
    "setInterval",
    "setTimeout",
    "std::thread::spawn",
];

const HANDLE_CONSUMERS: &[&str] = &[
    "await",
    "cancel",
    "abort",
    "clear",
    "clearInterval",
    "clearTimeout",
    "join",
    "shutdown",
    "wait",
];

impl Rule for EventLoopLeakRule {
    fn rule_id(&self) -> &'static str {
        "cc.memory.event_loop_leak"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Memory
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "spawn / setInterval handle never awaited or cancelled — leaks event loop refs"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Write) {
            if let Some(finding) = check_write(ctx, node) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_write(ctx: &RuleContext<'_>, write: &Node) -> Option<Finding> {
    let initializer = string_prop(ctx.batch, write.id, "initializer")?;
    if !is_spawn_producer(initializer) {
        return None;
    }
    let target = string_prop(ctx.batch, write.id, "target")?;
    let path = enclosing_file_path(ctx.batch, write.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let scope = enclosing_function(ctx.batch, write.id)?;
    if !is_async_function(ctx.batch, scope)
        && !initializer.contains("setInterval")
        && !initializer.contains("setTimeout")
        && !initializer.contains("std::thread::spawn")
    {
        return None;
    }
    if has_consumer_in_scope(ctx.batch, scope, target) {
        return None;
    }
    let location = location_from_node(ctx.batch, write.id, path);
    Some(build_finding(MemoryFindingBlueprint {
        rule_id: "cc.memory.event_loop_leak",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{target}` spawn handle never awaited / cancelled"),
        explanation: format!(
            "`{target}` is bound to a spawn / setInterval call but the handle \
             is never awaited, cancelled, aborted, or cleared in this function. \
             The runtime keeps a reference to the task forever — event-loop GC \
             cannot reclaim it."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Either `await` the handle, store it for later cancellation, or \
             explicitly fire-and-forget with a comment + lifecycle owner. For \
             interval / timeout primitives, pair every creation with a matching \
             clear-call in the same scope."
                .into(),
        ),
        snippet: initializer.to_owned(),
        weight: 3,
    }))
}

fn is_spawn_producer(initializer: &str) -> bool {
    SPAWN_PRODUCERS
        .iter()
        .any(|needle| initializer.contains(needle))
}

fn is_async_function(batch: &CpgWriteBatch, scope: NodeId) -> bool {
    if bool_prop(batch, scope, "is_async").unwrap_or(false) {
        return true;
    }
    string_prop(batch, scope, "modifiers").is_some_and(|m| m.contains("async"))
}

fn has_consumer_in_scope(batch: &CpgWriteBatch, scope: NodeId, target: &str) -> bool {
    nodes_of_kind(batch, NodeKind::Call).any(|call| {
        let receiver_matches = string_prop(batch, call.id, "receiver") == Some(target);
        let argument_matches = string_prop(batch, call.id, "callee_ref")
            .is_some_and(|c| HANDLE_CONSUMERS.iter().any(|k| c.contains(k)) && c.contains(target));
        let method_consumes =
            string_prop(batch, call.id, "method").is_some_and(|m| HANDLE_CONSUMERS.contains(&m));
        let same_scope = walks_to(batch, call.id, scope);
        same_scope && (receiver_matches && method_consumes || argument_matches)
    })
}

fn walks_to(batch: &CpgWriteBatch, mut id: NodeId, target: NodeId) -> bool {
    if id == target {
        return true;
    }
    for _ in 0..256_u16 {
        let Some(parent) = ast_parent(batch, id) else {
            return false;
        };
        if parent == target {
            return true;
        }
        if matches!(
            node_kind(batch, parent),
            Some(NodeKind::Function | NodeKind::Method)
        ) && parent != target
        {
            return false;
        }
        id = parent;
    }
    false
}
