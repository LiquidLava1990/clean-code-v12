//! `cc.modernize.simplify_boolean_expr` — `if cond { return true } else
//! { return false }` superseded by `return cond`.
//!
//! Mirrors clippy `needless_bool`, staticcheck `S1008`, ruff `SIM103`,
//! and pylint `simplifiable-if-statement`. Detection looks at
//! [`NodeKind::Function`] / [`NodeKind::Method`] nodes whose
//! `body_signature` (or fallback `signature`) string matches one of
//! the canonical "if/else returns true/false" shapes that frontends
//! lift across the four supported languages.
//!
//! Severity: `Nit` — semantically equivalent rewrite; pure style.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.simplify_boolean_expr`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SimplifyBooleanExprRule;

const SUPPORTED_EXTS: &[&str] = &[
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".rs", ".go",
];

const BODY_KEYS: &[&str] = &["body_signature", "body_text", "body", "signature"];

impl Rule for SimplifyBooleanExprRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.simplify_boolean_expr"
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
        "`if cond { return true } else { return false }` superseded by `return cond`"
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
    let body = function_body_text(ctx, node.id)?;
    if !looks_like_redundant_bool_return(&body) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, node.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !SUPPORTED_EXTS
        .iter()
        .any(|ext| path.as_str().ends_with(ext))
    {
        return None;
    }
    let fn_name = string_prop(ctx.batch, node.id, "name").unwrap_or("<anon>");
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.simplify_boolean_expr",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{fn_name}` returns the predicate it just tested"),
        explanation: "An `if cond { return true } else { return false }` \
             chain is a verbose way of writing `return cond`. The branch \
             adds no information, doubles the cyclomatic count, and hides \
             the boolean expression behind control flow."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace the entire `if/else` block with `return <cond>` (or \
             `return !<cond>` if the truthy branch returns false). Add \
             `bool(...)` if the predicate is not already boolean-typed."
                .into(),
        ),
        snippet: body,
        weight: 1,
    }))
}

fn function_body_text(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    for key in BODY_KEYS {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn looks_like_redundant_bool_return(body: &str) -> bool {
    let normalized = collapse_whitespace(body).to_ascii_lowercase();
    PATTERNS.iter().any(|p| normalized.contains(p))
}

/// Whitespace-collapsed, lower-cased substrings of the canonical
/// "redundant-bool-return" shape across Python / JS / TS / Rust / Go.
/// Python uses bare `else:`, the brace-languages use `} else {`, and
/// Rust/Go can drop the trailing semicolon — every variant collapses
/// to one of these forms after [`collapse_whitespace`].
const PATTERNS: &[&str] = &[
    "return true } else { return false",
    "return false } else { return true",
    "return true; } else { return false",
    "return false; } else { return true",
    "return true else: return false",
    "return false else: return true",
];

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}
