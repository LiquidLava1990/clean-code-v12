//! `cc.modernize.callbacks_over_promises` — JS/TS function whose last
//! parameter is named `cb` / `callback` / `done` and whose return type
//! is not a `Promise`.
//!
//! Heuristic-grade: the property surface across frontends is uneven, so
//! we scan [`NodeKind::Function`] / [`NodeKind::Method`] looking at the
//! `last_param_name` + `return_type` properties. When the frontend does
//! not surface either signal the probe stays silent rather than emit
//! noise.
//!
//! Severity: `Nit` — many legitimate codebases (Express, Mocha) still
//! ship callback-shaped APIs.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.callbacks_over_promises`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CallbacksOverPromisesRule;

const CALLBACK_NAMES: &[&str] = &["cb", "callback", "done", "next"];
const JS_EXTS: &[&str] = &[".js", ".jsx", ".mjs", ".ts", ".tsx"];

impl Rule for CallbacksOverPromisesRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.callbacks_over_promises"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "JS/TS function with trailing callback parameter; prefer Promise"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, node: &Node) -> Option<Finding> {
    let last_param = last_param_name(ctx, node.id)?;
    if !CALLBACK_NAMES.iter().any(|n| last_param == *n) {
        return None;
    }
    if returns_promise(ctx, node.id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, node.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let path_str = path.as_str();
    if !JS_EXTS.iter().any(|ext| path_str.ends_with(ext)) {
        return None;
    }
    let fn_name = string_prop(ctx.batch, node.id, "name").unwrap_or("<anon>");
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.callbacks_over_promises",
        severity: Severity::Nit,
        confidence: Confidence::new(0.5),
        location,
        headline: format!("`{fn_name}({last_param})` looks callback-shaped; prefer Promise"),
        explanation: format!(
            "`{fn_name}` ends in a `{last_param}` parameter — the classic \
             Node.js callback shape. Callbacks compose poorly (pyramid of \
             doom, manual error propagation), defeat `await`-based control \
             flow, and force every caller to either nest or `util.promisify`."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Return a `Promise<T>` and `await` it at the call site. Use \
             `util.promisify` to bridge legacy APIs you cannot rewrite."
                .into(),
        ),
        snippet: format!("function {fn_name}(..., {last_param})"),
        weight: 1,
    }))
}

fn last_param_name(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    for key in ["last_param_name", "trailing_param", "callback_param"] {
        if let Some(v) = string_prop(ctx.batch, id, key) {
            return Some(v.to_owned());
        }
    }
    let signature = string_prop(ctx.batch, id, "signature")?;
    extract_last_param(signature)
}

fn extract_last_param(signature: &str) -> Option<String> {
    let open = signature.find('(')?;
    let close = signature[open + 1..].rfind(')')?;
    let params = &signature[open + 1..open + 1 + close];
    let last = params.split(',').next_back()?.trim();
    let name = last.split(':').next()?.trim().trim_start_matches("...");
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

fn returns_promise(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    for key in ["return_type", "annotated_return", "inferred_return"] {
        if let Some(v) = string_prop(ctx.batch, id, key) {
            if v.contains("Promise") || v.contains("Awaitable") {
                return true;
            }
        }
    }
    string_prop(ctx.batch, id, "is_async") == Some("true")
}
