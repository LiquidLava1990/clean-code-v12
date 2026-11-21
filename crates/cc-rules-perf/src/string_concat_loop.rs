//! `cc.perf.string_concat_loop` — `s = s + x` / `s += x` inside a loop.
//!
//! Algorithm: every [`NodeKind::Write`] inside a [`NodeKind::Loop`] body
//! is inspected. If the write's `operator` lang_ext string is `+=`, or
//! the LHS Identifier's name suggests a string (`buf`, `out`, `s`,
//! `text`, `result`, `acc`) AND the write carries an `is_string_concat`
//! bool, the rule fires. Quadratic-time string concatenation in a loop is
//! one of the cheapest perf wins in the book.
//!
//! Phase-1 stub fallback: when no frontend signal is available the rule
//! skips silently. TODO(phase-3): wire `is_string_concat` from frontends.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{bool_prop, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_inside_loop, location_from_node, PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-STRING-CONCAT-LOOP.
#[derive(Debug, Default, Clone, Copy)]
pub struct StringConcatLoopRule;

/// Names that strongly suggest the binding holds a string buffer.
const STRING_NAME_HINTS: &[&str] = &["buf", "out", "text", "result", "acc", "s", "msg", "log"];

impl Rule for StringConcatLoopRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.string_concat_loop"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "string concatenation inside a loop — quadratic time"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Write) {
            if !is_inside_loop(ctx.batch, node.id) {
                continue;
            }
            if !looks_like_string_concat(ctx, node.id) {
                continue;
            }
            if let Some(finding) = emit(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

/// True iff the write looks like a string concat. Three independent
/// signals are accepted; any one is enough.
fn looks_like_string_concat(ctx: &RuleContext<'_>, write: NodeId) -> bool {
    if bool_prop(ctx.batch, write, "is_string_concat") == Some(true) {
        return true;
    }
    if string_prop(ctx.batch, write, "operator") == Some("+=") {
        if let Some(name) = string_prop(ctx.batch, write, "name") {
            return name_suggests_string(name);
        }
    }
    if string_prop(ctx.batch, write, "rhs_kind") == Some("binary_add") {
        if let Some(name) = string_prop(ctx.batch, write, "name") {
            return name_suggests_string(name);
        }
    }
    false
}

/// True iff `name` matches one of the canonical string-buffer hints.
fn name_suggests_string(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    STRING_NAME_HINTS.iter().any(|hint| {
        lower == *hint
            || lower.contains(&format!("_{hint}"))
            || lower.starts_with(&format!("{hint}_"))
    })
}

fn emit(ctx: &RuleContext<'_>, write: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, write)?;
    let name = string_prop(ctx.batch, write, "name").unwrap_or("<unknown>");
    let location = location_from_node(ctx.batch, write, path);
    Some(build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.string_concat_loop",
        severity: Severity::Required,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("string concat into `{name}` inside a loop"),
        explanation: format!(
            "Strings are immutable, so `{name} = {name} + ...` (or `{name} += ...`) \
             allocates a fresh buffer every iteration — total work grows \
             quadratically with the loop count. Build into a list / \
             `Vec<String>` / `bytes.Buffer` and join once after the loop."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Push fragments into a `list` / `Vec<String>` / `strings.Builder` \
             inside the loop and join / `to_string` once after it exits."
                .into(),
        ),
        snippet: String::new(),
        weight: 1,
    }))
}
