//! `cc.type.async_returns_null` — async function declared
//! `Promise<NonNullable>` returning `null` / `undefined`.
//!
//! Syntactic shadow of TypeScript ESLint's `no-confusing-non-null-assertion`
//! family; full version requires type-flow analysis. We approximate via:
//!
//! - The function is declared `async` (or returns `Promise<...>`).
//! - The declared return type is `Promise<T>` where `T` does not
//!   contain `null` / `undefined` / `?`.
//! - The function body's `return_expressions` property contains a
//!   literal `null` or `undefined` token as a return expression.
//!
//! Restricted to TypeScript. JavaScript has no static return types so
//! the rule degrades to silence there.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{bool_prop, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-ASYNC-RETURNS-NULL.
#[derive(Debug, Default, Clone, Copy)]
pub struct AsyncReturnsNullRule;

impl Rule for AsyncReturnsNullRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.async_returns_null"
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
        "async function returns null / undefined despite declared `Promise<NonNullable>` return type"
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
    let language = enclosing_file_language(ctx.batch, fn_id)?;
    if !is_typescript(&language) {
        return None;
    }
    if !is_async_function(ctx, fn_id) {
        return None;
    }
    let return_type = string_prop(ctx.batch, fn_id, "return_type")?;
    let inner = promise_inner_type(return_type)?;
    if allows_null(inner) {
        return None;
    }
    let returns = string_prop(ctx.batch, fn_id, "return_expressions").unwrap_or("");
    let trigger = classify_returns(returns)?;
    let path = enclosing_file_path(ctx.batch, fn_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let name = string_prop(ctx.batch, fn_id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.async_returns_null",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("async `{name}` returns {trigger} but declares `Promise<{inner}>`"),
        explanation: format!(
            "`{name}` is declared `Promise<{inner}>` (non-nullable) yet \
             returns {trigger}. Callers awaiting the promise will believe \
             they hold a `{inner}` and dereference fields on null at \
             runtime."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Either widen the return type to `Promise<T | null>` and let \
             callers handle the absence, or `throw new NotFoundError(...)` \
             for the missing case so the caller learns about it through \
             rejection rather than silent null."
                .into(),
        ),
        snippet: returns.to_owned(),
        weight: 4,
    }))
}

fn is_typescript(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "ts" | "typescript")
}

fn is_async_function(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    if bool_prop(ctx.batch, fn_id, "is_async").unwrap_or(false) {
        return true;
    }
    let signature = string_prop(ctx.batch, fn_id, "signature").unwrap_or("");
    signature.contains("async ") || signature.contains("async\n")
}

fn promise_inner_type(return_type: &str) -> Option<&str> {
    let trimmed = return_type.trim();
    let stripped = trimmed.strip_prefix("Promise<")?;
    let inner = stripped.strip_suffix('>')?;
    Some(inner.trim())
}

fn allows_null(inner: &str) -> bool {
    let lower = inner.to_ascii_lowercase();
    lower.contains("null")
        || lower.contains("undefined")
        || inner.contains('?')
        || inner == "void"
        || inner == "any"
        || inner == "unknown"
}

fn classify_returns(returns: &str) -> Option<&'static str> {
    for line in returns.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches("return ")
            .trim_end_matches(';')
            .trim();
        if trimmed == "null" {
            return Some("`null`");
        }
        if trimmed == "undefined" {
            return Some("`undefined`");
        }
    }
    None
}
