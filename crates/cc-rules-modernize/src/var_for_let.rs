//! `cc.modernize.var_for_let` — JavaScript `var` declarations.
//!
//! Mirrors `ESLint` `no-var` and unicorn `prefer-let-const`. Walks
//! [`NodeKind::Variable`] nodes and inspects the `declaration_kind` /
//! `signature` properties for the `var` keyword.
//!
//! Severity: `Required` — `var`'s function-scope semantics regularly
//! ship hoisting bugs; `let` / `const` are the modern default.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.var_for_let`.
#[derive(Debug, Default, Clone, Copy)]
pub struct VarForLetRule;

const JS_EXTS: &[&str] = &[".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"];

impl Rule for VarForLetRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.var_for_let"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "JavaScript `var` declaration superseded by `let` / `const`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Variable) {
            if let Some(finding) = check_variable(ctx, node) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_variable(ctx: &RuleContext<'_>, node: &Node) -> Option<Finding> {
    if !is_var_declaration(ctx, node.id) {
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
    let target = string_prop(ctx.batch, node.id, "name").unwrap_or("<binding>");
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.var_for_let",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`var {target}` should be `let` or `const`"),
        explanation: "`var` is hoisted to the enclosing function and ignores \
             block scope, which routinely produces aliasing bugs in `for` \
             loops and `if` blocks. `let` / `const` are block-scoped and \
             temporally dead until the declaration line."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `var` with `const` when the binding is not reassigned, \
             otherwise `let`."
                .into(),
        ),
        snippet: format!("var {target}"),
        weight: 1,
    }))
}

fn is_var_declaration(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    if string_prop(ctx.batch, id, "declaration_kind") == Some("var") {
        return true;
    }
    if string_prop(ctx.batch, id, "kind") == Some("var") {
        return true;
    }
    if let Some(sig) = string_prop(ctx.batch, id, "signature") {
        return sig.starts_with("var ") || sig.contains(" var ");
    }
    false
}
