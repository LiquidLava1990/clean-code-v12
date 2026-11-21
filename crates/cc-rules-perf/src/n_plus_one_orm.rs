//! `cc.perf.n_plus_one_orm` — ORM N+1 query smell.
//!
//! Algorithm: every [`NodeKind::Loop`] is examined. Inside its body we
//! search for a [`NodeKind::Call`] whose callee text matches a canonical
//! Django / SQLAlchemy / TypeORM access pattern (`.objects.all`,
//! `.objects.filter`, `.query(...).all()`). If the enclosing function's
//! body contains an explicit eager-load hint
//! (`prefetch_related|select_related|joinedload`), the loop is exempted
//! — the developer has already opted in to one-shot loading.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, enclosing_function, location_from_node,
    PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-N-PLUS-ONE-ORM.
#[derive(Debug, Default, Clone, Copy)]
pub struct NPlusOneOrmRule;

/// Substring patterns that mark an ORM lazy fetch.
const ORM_FETCH_HINTS: &[&str] = &[".objects.all", ".objects.filter", ".query(", ".all()"];

/// Substring patterns that mark an explicit eager-load opt-in. Their
/// presence anywhere in the enclosing function body suppresses the
/// finding because the slow path has already been addressed.
const EAGER_LOAD_HINTS: &[&str] = &["prefetch_related", "select_related", "joinedload"];

impl Rule for NPlusOneOrmRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.n_plus_one_orm"
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
        "ORM lazy fetch inside a loop without prefetch / select_related"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for loop_node in nodes_of_kind(ctx.batch, NodeKind::Loop) {
            collect_for_loop(ctx, loop_node.id, &mut out);
        }
        out
    }
}

fn collect_for_loop(ctx: &RuleContext<'_>, loop_id: NodeId, out: &mut Vec<Finding>) {
    let function = enclosing_function(ctx.batch, loop_id);
    if function.is_some_and(|fid| function_has_eager_load(ctx, fid)) {
        return;
    }
    walk_calls(ctx, loop_id, |id, text| {
        let Some(hit) = ORM_FETCH_HINTS.iter().find(|needle| text.contains(*needle)) else {
            return;
        };
        if let Some(finding) = emit(ctx, id, hit) {
            out.push(finding);
        }
    });
}

/// True iff any descendant call in the function's body mentions an
/// eager-load hint. Cheap whole-function scan; perf probes run per file.
fn function_has_eager_load(ctx: &RuleContext<'_>, function: NodeId) -> bool {
    let mut hit = false;
    walk_calls(ctx, function, |_id, text| {
        if !hit && EAGER_LOAD_HINTS.iter().any(|needle| text.contains(*needle)) {
            hit = true;
        }
    });
    hit
}

/// Walk every descendant `Call` node under `root` and invoke `visit` with
/// the call's id and resolved callee text. Iterative DFS — bounded by
/// AST size; terminates without stack growth on degenerate inputs.
fn walk_calls<F>(ctx: &RuleContext<'_>, root: NodeId, mut visit: F)
where
    F: FnMut(NodeId, &str),
{
    let mut stack: Vec<NodeId> = ast_children(ctx.batch, root).collect();
    while let Some(id) = stack.pop() {
        for child in ast_children(ctx.batch, id) {
            stack.push(child);
        }
        if node_kind(ctx.batch, id) != Some(NodeKind::Call) {
            continue;
        }
        let text = callee_text(ctx.batch, id);
        visit(id, &text);
    }
}

fn emit(ctx: &RuleContext<'_>, call: NodeId, hit: &str) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call)?;
    let location = location_from_node(ctx.batch, call, path);
    Some(build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.n_plus_one_orm",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("ORM fetch `{hit}` in loop without eager-load"),
        explanation: format!(
            "`{hit}` runs one DB round-trip per iteration — the classic \
             N+1 query smell. Replace with `prefetch_related` / \
             `select_related` (Django) or `joinedload` (SQLAlchemy) so the \
             ORM issues a single batched query before the loop."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Hoist the queryset above the loop with `prefetch_related` / \
             `select_related` / `joinedload` so the related rows arrive in \
             one round-trip instead of N."
                .into(),
        ),
        snippet: String::new(),
        weight: 3,
    }))
}
