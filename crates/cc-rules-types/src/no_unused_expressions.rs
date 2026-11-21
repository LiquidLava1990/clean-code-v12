//! `cc.type.no_unused_expressions` — expression-statement that has no
//! side effect.
//!
//! Syntactic shadow of TypeScript ESLint's `no-unused-expressions`.
//! Common shapes:
//!
//! - `x;` — bare identifier statement.
//! - `obj.foo;` — member access with no call.
//! - `1 + 2;` — arithmetic expression dropped.
//! - `"label";` — string literal statement (excluding `"use strict"`).
//!
//! The rule reads the `kind` / `expression` / `text` properties off
//! [`NodeKind::Read`], [`NodeKind::Literal`], and [`NodeKind::Identifier`]
//! nodes whose direct AST parent is a [`NodeKind::Block`] /
//! [`NodeKind::Module`] / [`NodeKind::File`]. If the expression has no
//! observable side effect, flag.
//!
//! Exclusions:
//! - String directives `"use strict"`, `"use client"`.
//! - Tagged template literals (frontend-specific marker).
//! - Conditional / short-circuit expressions used for side effect
//!   (`x && fn()` is permissive, but `x && y` without a call is flagged).
//!
//! TS/JS-only.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-UNUSED-EXPRESSIONS.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoUnusedExpressionsRule;

const ALLOWED_DIRECTIVES: &[&str] = &[
    "\"use strict\"",
    "'use strict'",
    "\"use client\"",
    "'use client'",
    "\"use server\"",
    "'use server'",
];

impl Rule for NoUnusedExpressionsRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_unused_expressions"
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
        "expression statement has no observable side effect"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Read, NodeKind::Identifier, NodeKind::Literal] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_node(ctx, node.id, kind) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_node(ctx: &RuleContext<'_>, id: NodeId, kind: NodeKind) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, id)?;
    if !is_ts_or_js(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if !is_ts_or_js_extension(path.as_str()) {
        return None;
    }
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !is_statement_position(ctx, id) {
        return None;
    }
    let text = node_text(ctx, id)?;
    if is_allowed(&text, kind) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    let trigger = describe_kind(kind);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_unused_expressions",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("unused expression statement ({trigger})"),
        explanation: format!(
            "The expression `{text}` is used as a statement but has no \
             observable side effect — the runtime evaluates it and \
             discards the result. Either call a function (the value was \
             probably meant to be invoked), assign the value (it was \
             probably meant to be captured), or delete the line."
        ),
        remediation: Remediation::SuggestedRewrite(
            "If the expression was meant to call something, add `()` or \
             the appropriate arguments. If the expression was meant to be \
             captured, assign it: `const x = <expr>;`. Otherwise delete \
             the line."
                .into(),
        ),
        snippet: text,
        weight: 1,
    }))
}

fn is_statement_position(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let Some(parent) = ast_parent(ctx.batch, id) else {
        return false;
    };
    matches!(
        node_kind(ctx.batch, parent),
        Some(NodeKind::Block | NodeKind::Module | NodeKind::File)
    )
}

fn node_text(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    for key in ["expression", "text", "value", "name"] {
        if let Some(text) = string_prop(ctx.batch, id, key) {
            if !text.is_empty() {
                return Some(text.to_owned());
            }
        }
    }
    None
}

fn is_allowed(text: &str, kind: NodeKind) -> bool {
    let trimmed = text.trim();
    if kind == NodeKind::Literal && ALLOWED_DIRECTIVES.iter().any(|d| *d == trimmed) {
        return true;
    }
    // Side-effect-bearing shapes: `x && fn()`, `x ?? fn()`, `x || fn()`,
    // assignment expressions, increment / decrement.
    if has_assignment(trimmed) {
        return true;
    }
    if has_call(trimmed) {
        return true;
    }
    if has_increment(trimmed) {
        return true;
    }
    false
}

fn has_assignment(text: &str) -> bool {
    let lower = text.replace(' ', "");
    let needles = ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "??="];
    for needle in needles {
        if let Some(idx) = lower.find(needle) {
            let next = lower.as_bytes().get(idx + needle.len()).copied();
            if next != Some(b'=') {
                return true;
            }
        }
    }
    false
}

fn has_call(text: &str) -> bool {
    text.contains('(') && text.contains(')')
}

fn has_increment(text: &str) -> bool {
    text.contains("++") || text.contains("--")
}

fn describe_kind(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Read => "bare member-access / variable read",
        NodeKind::Identifier => "bare identifier",
        NodeKind::Literal => "bare literal",
        _ => "expression",
    }
}

fn is_ts_or_js(language: &str) -> bool {
    matches!(
        language.to_ascii_lowercase().as_str(),
        "ts" | "typescript" | "js" | "javascript"
    )
}

fn is_ts_or_js_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".js")
        || lower.ends_with(".jsx")
}
