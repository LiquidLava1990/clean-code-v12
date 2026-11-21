//! `cc.type.no_non_null_assertion` — postfix `!` non-null assertion
//! (`x!.foo`, `arr[0]!`, `getThing()!`).
//!
//! Syntactic shadow of TypeScript ESLint's `no-non-null-assertion`. The
//! `!` operator tells the compiler "trust me, this is not null" with no
//! runtime check; if the assertion is wrong, the program crashes with a
//! cryptic error far from the bad assumption.
//!
//! Detection scans expression / statement text for the postfix `!`
//! pattern:
//! - `<ident>!.<member>` (member access through assertion)
//! - `<ident>!(` (call through assertion)
//! - `<ident>![` (index through assertion)
//! - `<ident>!;` / `<ident>!)` / `<ident>!,` (terminal assertion)
//!
//! Carefully excludes:
//! - `!=` / `!==` / `<= !` (logical / comparison `!`)
//! - `!x` prefix negation
//!
//! The detector reads the text from `expression`, `condition`, or
//! `arguments` properties on a [`NodeKind::Call`], [`NodeKind::Branch`],
//! [`NodeKind::Variable`], [`NodeKind::Write`], [`NodeKind::Return`]
//! adjacent. If no property carries the source text we skip silently.
//!
//! TS-only — JS does not parse `!` postfix assertions.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-NON-NULL-ASSERTION.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoNonNullAssertionRule;

const TEXT_PROPS: &[&str] = &["expression", "condition", "arguments", "text", "value"];

impl Rule for NoNonNullAssertionRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_non_null_assertion"
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
        "non-null assertion `!` lies to the type system without a runtime check"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [
            NodeKind::Call,
            NodeKind::Branch,
            NodeKind::Variable,
            NodeKind::Write,
            NodeKind::Read,
            NodeKind::Async,
        ] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_node(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_node(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, id)?;
    if !is_typescript(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if !is_ts_extension(path.as_str()) {
        return None;
    }
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let text = first_text(ctx, id)?;
    let snippet = find_non_null_assertion(text)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_non_null_assertion",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("non-null assertion `{snippet}` lies to the type system"),
        explanation: format!(
            "The postfix `!` in `{snippet}` tells the compiler \"trust me, \
             this is not null/undefined\" with no runtime check. When the \
             assumption is wrong, the resulting `Cannot read property of \
             null` lands far from the lying line and is hard to trace."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace the assertion with a real check: `if (x === null) throw …`, \
             optional chaining `x?.foo`, nullish coalescing `x ?? fallback`, \
             or pattern matching. If the value is genuinely guaranteed by \
             construction, encode that in the type (`NonNullable<T>`) so the \
             assertion becomes unnecessary."
                .into(),
        ),
        snippet: snippet.to_owned(),
        weight: 1,
    }))
}

fn is_typescript(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "ts" | "typescript")
}

fn is_ts_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts") || lower.ends_with(".tsx")
}

fn first_text<'b>(ctx: &RuleContext<'b>, id: NodeId) -> Option<&'b str> {
    for key in TEXT_PROPS {
        if let Some(text) = string_prop(ctx.batch, id, key) {
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn find_non_null_assertion(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    if len < 2 {
        return None;
    }
    let mut i = 1_usize;
    while i < len {
        if bytes[i] != b'!' {
            i += 1;
            continue;
        }
        if !is_postfix_position(bytes, i) {
            i += 1;
            continue;
        }
        if !is_followed_by_member_call_or_terminal(bytes, i) {
            i += 1;
            continue;
        }
        return Some(window_around(text, i));
    }
    None
}

fn is_postfix_position(bytes: &[u8], at: usize) -> bool {
    if at == 0 {
        return false;
    }
    let prev = bytes[at - 1];
    if !is_ident_or_close(prev) {
        return false;
    }
    if at + 1 < bytes.len() && bytes[at + 1] == b'=' {
        return false;
    }
    true
}

fn is_ident_or_close(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b')' | b']')
}

fn is_followed_by_member_call_or_terminal(bytes: &[u8], at: usize) -> bool {
    let next = bytes.get(at + 1).copied().unwrap_or(b' ');
    matches!(
        next,
        b'.' | b'(' | b'[' | b';' | b')' | b',' | b'}' | b' ' | b'\n'
    )
}

fn window_around(text: &str, idx: usize) -> &str {
    let bytes = text.as_bytes();
    let start = idx.saturating_sub(8);
    let end = (idx + 8).min(bytes.len());
    text.get(start..end).unwrap_or(text)
}
