//! `cc.type.no_misused_promise` — Promise passed where a sync value is
//! expected (the condition of an `if` / `while` / `||` / `&&` /
//! ternary).
//!
//! Syntactic shadow of TypeScript ESLint's `no-misused-promises`; full
//! version requires type-flow analysis. We approximate by walking
//! [`NodeKind::Branch`] and [`NodeKind::Loop`] nodes, reading the
//! `condition` string property the frontend exposes, and matching
//! syntactic indicators that the condition is an async call:
//!
//! - The condition contains `<ident>Async(`
//! - The condition starts with `async ` or `await ` (await is sync but
//!   indicates the author confused the boundary; we let probe 1 handle
//!   the bare `async fn()` case and skip here).
//! - The condition matches a known Promise-producing call (`fetch(`,
//!   `axios.`, `Promise.`, `.then(`, `.catch(`).
//!
//! The bare `await someAsync()` case is intentionally skipped — that is
//! correct usage. We fire only when the condition expression evaluates
//! a Promise without unwrapping it.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-MISUSED-PROMISE.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoMisusedPromiseRule;

const PROMISE_NEEDLES: &[&str] = &["fetch(", "axios.", "Promise.", ".then(", ".catch("];

impl Rule for NoMisusedPromiseRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_misused_promise"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Promise used where a sync boolean / value is expected (if / while / && / ||)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Branch, NodeKind::Loop] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_condition(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_condition(ctx: &RuleContext<'_>, node_id: NodeId) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, node_id)?;
    if !is_ts_or_js(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, node_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let condition = string_prop(ctx.batch, node_id, "condition")?;
    if !condition_is_promise(condition) {
        return None;
    }
    let location = location_from_node(ctx.batch, node_id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_misused_promise",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("Promise used as boolean in condition `{condition}`"),
        explanation: format!(
            "The condition `{condition}` evaluates a Promise — Promises are \
             always truthy, so the branch becomes unreachable / always-taken. \
             Either `await` the call or check `(await fn()).result` to \
             evaluate the resolved value."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Mark the enclosing function `async` and `await` the promise \
             before the condition: `if (await someAsync()) { ... }`. If the \
             caller cannot be async, restructure with `.then(value => { if \
             (value) { ... } })`."
                .into(),
        ),
        snippet: condition.to_owned(),
        weight: 3,
    }))
}

fn is_ts_or_js(language: &str) -> bool {
    matches!(
        language.to_ascii_lowercase().as_str(),
        "ts" | "typescript" | "js" | "javascript"
    )
}

fn condition_is_promise(condition: &str) -> bool {
    let trimmed = condition.trim();
    if trimmed.starts_with("await ") {
        return false;
    }
    if PROMISE_NEEDLES
        .iter()
        .any(|needle| trimmed.contains(needle))
    {
        return true;
    }
    contains_async_suffix_call(trimmed)
}

fn contains_async_suffix_call(text: &str) -> bool {
    let mut chars = text.char_indices().peekable();
    while let Some((idx, c)) = chars.next() {
        if c != 'A' {
            continue;
        }
        if !text[idx..].starts_with("Async(") {
            continue;
        }
        let prefix_ok = idx
            .checked_sub(1)
            .and_then(|p| text.as_bytes().get(p))
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if prefix_ok {
            return true;
        }
    }
    false
}
