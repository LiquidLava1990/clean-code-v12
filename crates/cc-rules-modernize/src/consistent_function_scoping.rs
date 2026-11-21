//! `cc.modernize.consistent_function_scoping` — JS/TS nested function
//! that captures no binding from its enclosing scope, so it could be
//! hoisted out without behaviour change.
//!
//! Mirrors eslint-plugin-unicorn `consistent-function-scoping`.
//!
//! Heuristic detection: any [`NodeKind::Function`] /
//! [`NodeKind::Method`] node whose AST parent is *another* Function /
//! Method node (i.e. a nested definition) and whose `captures` /
//! `free_vars` property either reports zero captures or is missing
//! while the `body_signature` does not reference any of the parent's
//! parameters by name.
//!
//! Severity: `Nit`, confidence `0.8` — frontends that don't surface
//! capture sets force this probe back onto the heuristic, which is
//! good enough for Phase-8 modernization warnings but not strict
//! correctness.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.consistent_function_scoping`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConsistentFunctionScopingRule;

const JS_EXTS: &[&str] = &[".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"];

const CAPTURE_KEYS: &[&str] = &["captures", "free_vars", "closure_vars"];

const BODY_KEYS: &[&str] = &["body_signature", "body_text", "body", "signature"];

impl Rule for ConsistentFunctionScopingRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.consistent_function_scoping"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "JS/TS nested function with no enclosing-scope capture should be hoisted"
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
    let parent_fn = enclosing_function(ctx, node.id)?;
    if !function_is_independent(ctx, node.id, parent_fn) {
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
    if path_str.contains("node_modules") {
        return None;
    }
    let inner_name = string_prop(ctx.batch, node.id, "name").unwrap_or("<anon>");
    let outer_name = string_prop(ctx.batch, parent_fn, "name").unwrap_or("<anon>");
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.consistent_function_scoping",
        severity: Severity::Nit,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("`{inner_name}` (inside `{outer_name}`) captures nothing — hoist it"),
        explanation: format!(
            "`{inner_name}` is defined inside `{outer_name}` but does not \
             reference any of its parameters or locals. Defining it inline \
             reallocates the function object on every call, prevents \
             reuse, and makes the call graph harder to read. Hoisting the \
             definition to module scope keeps a single closure-free \
             function visible to the whole module."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Move `{inner_name}` out of `{outer_name}` to module scope (or \
             a sibling declaration). If the inner function intentionally \
             closes over `this`, switch to an arrow function and capture \
             explicitly."
        )),
        snippet: format!("function {inner_name}(...) {{ ... }}"),
        weight: 1,
    }))
}

fn enclosing_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<NodeId> {
    let mut cursor = ast_parent(ctx.batch, id)?;
    for _ in 0..256_u16 {
        match node_kind(ctx.batch, cursor) {
            Some(NodeKind::Function | NodeKind::Method) => return Some(cursor),
            Some(NodeKind::File | NodeKind::Module | NodeKind::Class) => return None,
            _ => {}
        }
        cursor = ast_parent(ctx.batch, cursor)?;
    }
    None
}

fn function_is_independent(ctx: &RuleContext<'_>, inner: NodeId, outer: NodeId) -> bool {
    if let Some(captures) = captures_property(ctx, inner) {
        return captures.trim() == "0" || captures.trim().is_empty() || captures == "[]";
    }
    let Some(body) = body_text(ctx, inner) else {
        return false;
    };
    let outer_params = outer_param_names(ctx, outer);
    if outer_params.is_empty() {
        // No parameters declared upstream — a nested function with no
        // free vars in any of the parent's params can still be hoisted.
        return true;
    }
    !outer_params
        .iter()
        .any(|name| body_references_identifier(&body, name))
}

fn captures_property(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    for key in CAPTURE_KEYS {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            return Some(value.to_owned());
        }
    }
    None
}

fn body_text(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    for key in BODY_KEYS {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn outer_param_names(ctx: &RuleContext<'_>, outer: NodeId) -> Vec<String> {
    for key in ["param_names", "parameters", "params", "signature"] {
        let Some(value) = string_prop(ctx.batch, outer, key) else {
            continue;
        };
        let params = parse_param_list(value);
        if !params.is_empty() {
            return params;
        }
    }
    Vec::new()
}

fn parse_param_list(value: &str) -> Vec<String> {
    value
        .split([',', '|', ';', ' '])
        .filter_map(extract_identifier_name)
        .collect()
}

fn extract_identifier_name(piece: &str) -> Option<String> {
    let cleaned = piece
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_start_matches("...");
    let name = cleaned.split(':').next()?.trim();
    if name.is_empty() || !name.chars().all(is_identifier_char) {
        return None;
    }
    Some(name.to_owned())
}

fn body_references_identifier(body: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    let bytes = body.as_bytes();
    let needle = ident.as_bytes();
    let mut idx = 0usize;
    while idx + needle.len() <= bytes.len() {
        if &bytes[idx..idx + needle.len()] == needle {
            let before = if idx == 0 { None } else { Some(bytes[idx - 1]) };
            let after = bytes.get(idx + needle.len()).copied();
            if !is_word_byte(before) && !is_word_byte(after) {
                return true;
            }
        }
        idx += 1;
    }
    false
}

fn is_word_byte(byte: Option<u8>) -> bool {
    match byte {
        None => false,
        Some(b) => (b as char).is_ascii_alphanumeric() || b == b'_' || b == b'$',
    }
}

fn is_identifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}
