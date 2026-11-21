//! `cc.type.await_thenable` — `await <literal>` / `await <object-literal>`.
//!
//! Syntactic shadow of TypeScript ESLint's `await-thenable`; full
//! version requires type-flow analysis to know whether a value
//! implements `then`. We approximate the unambiguous case: awaiting a
//! plain literal (`await 42`, `await "x"`, `await true`, `await null`,
//! `await { foo: 1 }`) is always wrong — the runtime wraps the value
//! in `Promise.resolve` and resolves immediately, so the `await` is
//! pure noise that masks the real intent.
//!
//! Detected via [`NodeKind::Async`] nodes whose `expression` string
//! property is recognisably literal. Restricted to `ts` / `typescript`
//! / `js` / `javascript`.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-AWAIT-THENABLE.
#[derive(Debug, Default, Clone, Copy)]
pub struct AwaitThenableRule;

impl Rule for AwaitThenableRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.await_thenable"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "`await` applied to a literal / object-literal — always a no-op"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Async) {
            if let Some(finding) = check_await(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_await(ctx: &RuleContext<'_>, async_id: NodeId) -> Option<Finding> {
    let kind = string_prop(ctx.batch, async_id, "kind").unwrap_or("await");
    if kind != "await" {
        return None;
    }
    let language = enclosing_file_language(ctx.batch, async_id)?;
    if !is_ts_or_js(&language) {
        return None;
    }
    let expression = string_prop(ctx.batch, async_id, "expression")?;
    let trigger = classify_expression(expression)?;
    let path = enclosing_file_path(ctx.batch, async_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, async_id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.await_thenable",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("`await {expression}` is a no-op ({trigger})"),
        explanation: format!(
            "`await` on {trigger} resolves immediately with the same value \
             — the await yields the event loop for one tick and then \
             returns the literal unchanged. Either drop the `await` or, if \
             the value should genuinely be async, replace the literal with \
             the actual promise-returning expression."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Remove the `await` — the expression is not thenable. If the \
             yield was intentional (force-microtask), use `await Promise.resolve()` \
             with a comment explaining why the deferral is needed."
                .into(),
        ),
        snippet: expression.to_owned(),
        weight: 1,
    }))
}

fn is_ts_or_js(language: &str) -> bool {
    matches!(
        language.to_ascii_lowercase().as_str(),
        "ts" | "typescript" | "js" | "javascript"
    )
}

fn classify_expression(expression: &str) -> Option<&'static str> {
    let trimmed = expression.trim();
    if trimmed.is_empty() {
        return None;
    }
    let keyword = match trimmed {
        "true" | "false" => Some("a boolean literal"),
        "null" | "undefined" => Some("a null/undefined literal"),
        _ => None,
    };
    if keyword.is_some() {
        return keyword;
    }
    classify_shape(trimmed)
}

fn classify_shape(trimmed: &str) -> Option<&'static str> {
    let table: &[(fn(&str) -> bool, &'static str)] = &[
        (is_string_literal, "a string literal"),
        (is_number_literal, "a number literal"),
        (is_object_literal, "an object literal"),
        (is_array_literal, "an array literal"),
    ];
    for (predicate, label) in table {
        if predicate(trimmed) {
            return Some(*label);
        }
    }
    None
}

fn is_array_literal(text: &str) -> bool {
    text.starts_with('[') && text.ends_with(']')
}

fn is_string_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    let len = bytes.len();
    if len < 2 {
        return false;
    }
    let first = bytes[0];
    let last = bytes[len - 1];
    matches!(first, b'"' | b'\'' | b'`') && first == last
}

fn is_number_literal(text: &str) -> bool {
    text.parse::<f64>().is_ok()
}

fn is_object_literal(text: &str) -> bool {
    text.starts_with('{') && text.ends_with('}')
}
