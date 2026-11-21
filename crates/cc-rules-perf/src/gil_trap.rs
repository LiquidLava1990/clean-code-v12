//! `cc.perf.gil_trap` — Python `async def` that never yields.
//!
//! Python coroutines must hit at least one `await` to release the event
//! loop. A long-bodied `async def` with no `Async` descendants holds the
//! GIL for its entire runtime, defeating the whole point of the async
//! runtime. We approximate "long" as > 20 logical lines via the function
//! `range` property, and "never yields" as zero [`NodeKind::Async`]
//! descendants in the body.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{
    ast_children, ast_parent, bool_prop, node_kind, nodes_of_kind, range_prop, string_prop,
};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-GIL-TRAP.
#[derive(Debug, Default, Clone, Copy)]
pub struct GilTrapRule;

/// Body-length threshold (logical lines) below which the rule stays
/// silent. Mirrors the spec.
const MIN_BODY_LINES: u32 = 20;

impl Rule for GilTrapRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.gil_trap"
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
        "Python async function with no `await` — never yields the GIL"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if !is_python_async(ctx, node.id) {
                    continue;
                }
                if body_line_count(ctx, node.id) <= MIN_BODY_LINES {
                    continue;
                }
                if has_async_descendant(ctx, node.id) {
                    continue;
                }
                if let Some(finding) = emit(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

/// True iff `id` is `is_async = true` AND the file's `language` prop is
/// "python". Walks the AST_PARENT chain to the enclosing File once.
fn is_python_async(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    if bool_prop(ctx.batch, id, "is_async") != Some(true) {
        return false;
    }
    let mut cursor = id;
    for _ in 0..256_u16 {
        if node_kind(ctx.batch, cursor) == Some(NodeKind::File) {
            return string_prop(ctx.batch, cursor, "language") == Some("python");
        }
        let Some(parent) = ast_parent(ctx.batch, cursor) else {
            return false;
        };
        cursor = parent;
    }
    false
}

/// Approximate body length using the function node's `range` prop.
fn body_line_count(ctx: &RuleContext<'_>, id: NodeId) -> u32 {
    range_prop(ctx.batch, id, "range")
        .map(|r| r.end.line.saturating_sub(r.start.line))
        .unwrap_or(0)
}

/// True iff the function body contains any [`NodeKind::Async`] descendant
/// or any descendant whose own `is_await` lang_ext bool is set.
fn has_async_descendant(ctx: &RuleContext<'_>, function: NodeId) -> bool {
    let mut stack: Vec<NodeId> = ast_children(ctx.batch, function).collect();
    while let Some(id) = stack.pop() {
        if node_kind(ctx.batch, id) == Some(NodeKind::Async) {
            return true;
        }
        if bool_prop(ctx.batch, id, "is_await") == Some(true) {
            return true;
        }
        for child in ast_children(ctx.batch, id) {
            stack.push(child);
        }
    }
    false
}

fn emit(ctx: &RuleContext<'_>, function: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, function)?;
    let name = string_prop(ctx.batch, function, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, function, path);
    Some(build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.gil_trap",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("async function `{name}` never awaits — holds the GIL"),
        explanation: format!(
            "`async def {name}` runs > {MIN_BODY_LINES} lines without a single \
             `await`, so the coroutine never yields control back to the event \
             loop. Either await an async I/O call inside the body or convert \
             the function to a regular `def` and dispatch via \
             `asyncio.to_thread` when called."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add an explicit `await` for the I/O the function performs, or \
             drop `async` and run the work via `asyncio.to_thread` from the \
             caller."
                .into(),
        ),
        snippet: String::new(),
        weight: 2,
    }))
}
