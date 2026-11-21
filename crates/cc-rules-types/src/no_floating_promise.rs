//! `cc.type.no_floating_promise` — async/Promise-returning expression
//! discarded as a bare statement (`fetch(url);`, `someAsync();`).
//!
//! Syntactic shadow of TypeScript ESLint's `no-floating-promises`; full
//! version requires type-flow analysis to know whether the callee
//! returns `Promise<T>`. We approximate via three signals:
//!
//! - The call's [`callee_text`] matches
//!   a known async producer (`fetch`, `axios.get`, `.then(`, `.catch(`).
//! - The callee identifier ends with `Async` (`saveDataAsync()`).
//! - The function's declaration text (when the frontend exposes it as
//!   `async_callee` / `is_async_callee`) marks it async.
//!
//! The rule fires only when the `Call` is the immediate child of a
//! [`NodeKind::Block`] (i.e. an expression-statement) AND no enclosing
//! [`NodeKind::Async`] / `Return` / `Write` swallows the result. Files
//! whose `language` is not `ts` / `js` / `typescript` / `javascript`
//! are skipped.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{
    ast_parent, bool_prop, callee_text, node_kind, nodes_of_kind, string_prop,
};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-FLOATING-PROMISE.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoFloatingPromiseRule;

const ASYNC_PRODUCER_NEEDLES: &[&str] = &[
    "fetch(",
    "axios.",
    ".then(",
    ".catch(",
    ".finally(",
    "Promise.",
    "setTimeout(",
    "setInterval(",
];

impl Rule for NoFloatingPromiseRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_floating_promise"
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
        "Promise-returning call used as a bare statement without await / .then / .catch"
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

fn check_call(ctx: &RuleContext<'_>, call_id: NodeId) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, call_id)?;
    if !is_ts_or_js(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, call_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !is_promise_returning(ctx, call_id) {
        return None;
    }
    if !is_floating_statement(ctx, call_id) {
        return None;
    }
    let callee = callee_text(ctx.batch, call_id);
    let location = location_from_node(ctx.batch, call_id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_floating_promise",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{callee}` returns a Promise but is dropped on the floor"),
        explanation: format!(
            "`{callee}` is async / Promise-returning but the result is \
             discarded as a bare statement. Unhandled rejections crash the \
             process under Node 15+ and silently corrupt state under \
             Node 14. Either `await` the call, attach `.then(...).catch(...)`, \
             or capture the promise and pass it on."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add `await` (inside an async function) or `.catch(handler)` to \
             the call. If the caller is intentionally fire-and-forget, mark \
             with `void <expr>` or `// fire-and-forget: <reason>` so the \
             intent is explicit."
                .into(),
        ),
        snippet: callee,
        weight: 3,
    }))
}

fn is_ts_or_js(language: &str) -> bool {
    matches!(
        language.to_ascii_lowercase().as_str(),
        "ts" | "typescript" | "js" | "javascript"
    )
}

fn is_promise_returning(ctx: &RuleContext<'_>, call_id: NodeId) -> bool {
    if bool_prop(ctx.batch, call_id, "is_async_callee").unwrap_or(false) {
        return true;
    }
    let callee = callee_text(ctx.batch, call_id);
    if callee.is_empty() {
        return false;
    }
    if ASYNC_PRODUCER_NEEDLES
        .iter()
        .any(|needle| callee.contains(needle))
    {
        return true;
    }
    callee_ends_with_async(&callee)
}

fn callee_ends_with_async(callee: &str) -> bool {
    callee
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|seg| !seg.is_empty())
        .any(|seg| seg.ends_with("Async") && seg != "Async")
}

fn is_floating_statement(ctx: &RuleContext<'_>, call_id: NodeId) -> bool {
    let Some(parent) = ast_parent(ctx.batch, call_id) else {
        return false;
    };
    match node_kind(ctx.batch, parent) {
        Some(NodeKind::Block | NodeKind::Module | NodeKind::File) => {}
        _ => return false,
    }
    if has_swallowing_ancestor(ctx, call_id) {
        return false;
    }
    !has_chained_handler(ctx, call_id)
}

fn has_swallowing_ancestor(ctx: &RuleContext<'_>, call_id: NodeId) -> bool {
    let mut cursor = call_id;
    for _ in 0..8_u8 {
        let Some(parent) = ast_parent(ctx.batch, cursor) else {
            return false;
        };
        match node_kind(ctx.batch, parent) {
            Some(NodeKind::Async | NodeKind::Return | NodeKind::Write) => return true,
            Some(NodeKind::Block | NodeKind::Module | NodeKind::File) => return false,
            _ => cursor = parent,
        }
    }
    false
}

fn has_chained_handler(ctx: &RuleContext<'_>, call_id: NodeId) -> bool {
    let suffix = string_prop(ctx.batch, call_id, "trailing").unwrap_or("");
    suffix.contains(".then(")
        || suffix.contains(".catch(")
        || suffix.contains(".finally(")
        || suffix.starts_with("await ")
        || suffix.starts_with("void ")
}
