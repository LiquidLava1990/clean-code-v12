//! `cc.obs.missing_metrics` — public function on a critical path with
//! external I/O but no metric primitive.
//!
//! Heuristic: enumerate every [`NodeKind::Function`] / [`NodeKind::Method`]
//! node. A function is "public" when its `visibility` property is
//! `"public"`, or absent (Phase-4 conservative default for languages
//! that do not surface visibility). For each public function we walk
//! AST descendants for [`NodeKind::Call`] nodes and ask:
//!
//! - is at least one Call's callee text in
//!   [`crate::helpers::EXTERNAL_IO_CALLEES`]? (critical path)
//! - is NO Call's callee text in [`crate::helpers::METRIC_CALLEES`]?
//!   (no metric coverage)
//!
//! Both true -> fire.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_matches, callee_text, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, ObsFindingBlueprint, EXTERNAL_IO_CALLEES,
    METRIC_CALLEES,
};

/// Family-11 probe R-OBS-MISSING-METRICS.
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingMetricsRule;

impl Rule for MissingMetricsRule {
    fn rule_id(&self) -> &'static str {
        "cc.obs.missing_metrics"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "public function on a critical path emits no latency / error metric"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, fn_id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, fn_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !is_public(ctx, fn_id) {
        return None;
    }
    let texts = collect_call_texts(ctx, fn_id);
    if !texts.iter().any(|t| callee_matches(t, EXTERNAL_IO_CALLEES)) {
        return None;
    }
    if texts.iter().any(|t| callee_matches(t, METRIC_CALLEES)) {
        return None;
    }
    let name = string_prop(ctx.batch, fn_id, "name")
        .unwrap_or("<anonymous>")
        .to_owned();
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(emit(location, &name))
}

fn is_public(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    string_prop(ctx.batch, fn_id, "visibility")
        .map_or(true, |v| matches!(v, "public" | "pub" | "exported"))
}

fn collect_call_texts(ctx: &RuleContext<'_>, fn_id: NodeId) -> Vec<String> {
    let mut out = Vec::new();
    let mut frontier = vec![fn_id];
    let mut visited: u32 = 0;
    while let Some(cur) = frontier.pop() {
        visited = visited.saturating_add(1);
        if visited > 4096 {
            break;
        }
        for child in ast_children(ctx.batch, cur) {
            if node_kind(ctx.batch, child) == Some(NodeKind::Call) {
                out.push(callee_text(ctx.batch, child));
            }
            frontier.push(child);
        }
    }
    out
}

fn emit(location: cc_finding::Location, name: &str) -> Finding {
    build_finding(ObsFindingBlueprint {
        rule_id: "cc.obs.missing_metrics",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{name}` performs external I/O without emitting any metric"),
        explanation: format!(
            "`{name}` makes a database / HTTP / filesystem call but emits \
             no histogram / counter / span. When this function regresses \
             — slowly or suddenly — there is nothing in the metric system \
             to alert on. Every public critical-path function needs at \
             least a latency histogram and an error counter."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the body with a latency histogram (e.g. \
             `metrics::histogram!(\"...\", elapsed)`) and increment an \
             error counter on the failure path. Rust callers can use \
             `tracing::info_span!` + `instrument` for the same coverage."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 2,
    })
}
