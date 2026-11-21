//! `cc.perf.gc_pressure` — list-comprehension materialised solely to be
//! consumed by a one-shot reducer.
//!
//! Algorithm: every [`NodeKind::Call`] whose callee text matches a
//! canonical reducer name (`sum`, `max`, `min`, `any`, `all`) gets its
//! arguments inspected; if the first argument is itself a Call /
//! Identifier whose `is_list_comprehension` lang_ext bool is true, we
//! emit a finding suggesting a generator expression instead. The
//! materialised list adds peak memory plus GC pressure for no gain.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, bool_prop, node_kind, nodes_of_kind};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, location_from_node, PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-GC-PRESSURE.
#[derive(Debug, Default, Clone, Copy)]
pub struct GcPressureRule;

/// Reducers that consume their iterable in one pass and never need a
/// materialised list.
const REDUCERS: &[&str] = &["sum", "max", "min", "any", "all"];

impl Rule for GcPressureRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.gc_pressure"
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
        "list-comprehension materialised for a one-shot reducer"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if !is_reducer(ctx, node.id) {
                continue;
            }
            if !first_arg_is_listcomp(ctx, node.id) {
                continue;
            }
            if let Some(finding) = emit(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

/// True iff the call's callee text matches a canonical reducer.
fn is_reducer(ctx: &RuleContext<'_>, call: NodeId) -> bool {
    let text = callee_text(ctx.batch, call);
    REDUCERS.iter().any(|name| {
        text == *name || text.ends_with(&format!(".{name}")) || text.contains(&format!(" {name}"))
    })
}

/// True iff any direct AST child of the reducer call carries the
/// `is_list_comprehension` lang_ext bool. Frontends that haven't
/// emitted the flag never trigger the rule, which matches the stub
/// fallback contract — no false positives without signal.
fn first_arg_is_listcomp(ctx: &RuleContext<'_>, call: NodeId) -> bool {
    for child in ast_children(ctx.batch, call) {
        if !matches!(
            node_kind(ctx.batch, child),
            Some(NodeKind::Call | NodeKind::Identifier | NodeKind::Read)
        ) {
            continue;
        }
        if bool_prop(ctx.batch, child, "is_list_comprehension") == Some(true) {
            return true;
        }
    }
    false
}

fn emit(ctx: &RuleContext<'_>, call: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call)?;
    let location = location_from_node(ctx.batch, call, path);
    Some(build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.gc_pressure",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "list-comprehension feeds a one-shot reducer".into(),
        explanation: "A list comprehension passed straight into `sum` / `max` / `min` / \
             `any` / `all` materialises the entire intermediate list before \
             the reducer consumes it. Drop the brackets — a generator \
             expression streams the values and avoids the GC churn."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `sum([... for ... in ...])` with `sum(... for ... in ...)` \
             — the generator form skips the materialised list."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}
