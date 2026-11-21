//! `cc.modernize.no_array_for_each` — `arr.forEach(cb)` superseded by
//! `for (const x of arr)`.
//!
//! Mirrors eslint-plugin-unicorn `no-array-for-each` and ts-eslint's
//! `prefer-for-of`. Detection: any [`NodeKind::Call`] whose canonical
//! callee text ends in `.forEach` (or contains a member chain ending
//! in `.forEach`) inside a JS/TS source file.
//!
//! Severity: `Nit` — `forEach` works correctly; the for-of form is
//! just async-friendly (`await` works inside) and skips the per-call
//! function frame.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.no_array_for_each`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoArrayForEachRule;

const JS_EXTS: &[&str] = &[".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"];

impl Rule for NoArrayForEachRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.no_array_for_each"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "JS/TS `arr.forEach(cb)` superseded by `for (const x of arr)`"
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

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let text = callee_text(ctx.batch, id);
    if !is_for_each_call(&text) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let path_str = path.as_str();
    if !JS_EXTS.iter().any(|ext| path_str.ends_with(ext)) {
        return None;
    }
    if path_str.contains("node_modules") {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.no_array_for_each",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: "`Array.prototype.forEach` superseded by `for…of`".into(),
        explanation: "`forEach` ignores `await` (the callback runs to \
             completion before the next iteration starts, but the outer \
             scope sees the iterations as already-resolved), forbids `break`, \
             and pays a function-frame per element. `for (const x of arr)` \
             keeps `await`, `break`, `continue`, and `return` working as \
             ordinary control flow."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `arr.forEach((x) => body)` with \
             `for (const x of arr) { body }`. When you only need the index, \
             use `for (let i = 0; i < arr.length; i++)`. \
             For Promise-returning callbacks switch to \
             `await Promise.all(arr.map(cb))`."
                .into(),
        ),
        snippet: text,
        weight: 1,
    }))
}

fn is_for_each_call(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    text.ends_with(".forEach")
        || text.contains(".forEach(")
        || text.contains(".forEach ")
        || text == "forEach"
}
