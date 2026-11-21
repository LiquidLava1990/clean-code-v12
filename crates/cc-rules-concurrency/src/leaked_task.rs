//! `cc.concurrent.leaked_task` — async-spawn calls whose return value is
//! discarded and whose body is never awaited.
//!
//! Heuristic: walk every [`NodeKind::Call`] whose callee matches an
//! async-spawn primitive (`asyncio.create_task`, `tokio::spawn`,
//! `setTimeout`, `setInterval`). If the call's parent isn't a Write
//! (assignment or `let` binding) AND no sibling `await` / `.await`
//! references the call, flag the spawn as leaked.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, enclosing_function, location_from_node,
    looks_like_rule_pack_source, ConcurrencyFindingBlueprint,
};

/// Family-5 probe R-CONCURRENT-LEAKED-TASK.
#[derive(Debug, Default, Clone, Copy)]
pub struct LeakedTaskRule;

/// Closed list of async-spawn callee texts. Substring match.
const SPAWN_CALLEES: &[&str] = &[
    "asyncio.create_task",
    "asyncio.ensure_future",
    "tokio::spawn",
    "tokio::task::spawn",
    "setTimeout",
    "setInterval",
];

impl Rule for LeakedTaskRule {
    fn rule_id(&self) -> &'static str {
        "cc.concurrent.leaked_task"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Concurrent
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "async-spawn whose handle is dropped and never awaited"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, call: NodeId) -> Option<Finding> {
    let callee = callee_text(ctx.batch, call);
    if !SPAWN_CALLEES.iter().any(|needle| callee.contains(needle)) {
        return None;
    }
    if parent_is_assignment(ctx, call) {
        return None;
    }
    if function_has_await(ctx, call) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, call)?;
    if looks_like_rule_pack_source(&path) {
        // Rule packs embed spawn-callee names (`setTimeout`,
        // `setInterval`, `tokio::spawn`, ...) as substrings inside their
        // remediation messages and string-literal fixtures. Substring
        // matching the source bytes flags the detector for owning the
        // shape it scans for — skip until the AST detector lands.
        return None;
    }
    let location = location_from_node(ctx.batch, call, path);
    Some(build_finding(ConcurrencyFindingBlueprint {
        rule_id: "cc.concurrent.leaked_task",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{callee}` return value is discarded and never awaited"),
        explanation: format!(
            "`{callee}` schedules work asynchronously; if the handle is \
             dropped without `await`, exceptions are swallowed and the \
             task may be cancelled at GC time. Bind the handle and await \
             it, or document the fire-and-forget intent explicitly."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Bind to a variable and `await` it, store it on a tracked task \
             set (`asyncio.gather`, `JoinSet`), or wrap the spawn in an \
             explicit `# fire-and-forget` helper that documents the \
             accepted leak."
                .into(),
        ),
        snippet: callee,
        weight: 3,
    }))
}

fn parent_is_assignment(ctx: &RuleContext<'_>, call: NodeId) -> bool {
    let Some(parent) = ast_parent(ctx.batch, call) else {
        return false;
    };
    matches!(
        node_kind(ctx.batch, parent),
        Some(NodeKind::Write | NodeKind::Variable | NodeKind::Return)
    )
}

/// True iff the enclosing function contains any `Async` node (await /
/// async with). Used as a coarse "the spawn is being awaited somewhere"
/// proxy — phase-3 ships heuristic-grade.
fn function_has_await(ctx: &RuleContext<'_>, call: NodeId) -> bool {
    let Some(fun) = enclosing_function(ctx.batch, call) else {
        return false;
    };
    let mut stack: Vec<NodeId> = cc_frontend::query::ast_children(ctx.batch, fun).collect();
    while let Some(id) = stack.pop() {
        for child in cc_frontend::query::ast_children(ctx.batch, id) {
            stack.push(child);
        }
        if node_kind(ctx.batch, id) == Some(NodeKind::Async) {
            return true;
        }
    }
    false
}
