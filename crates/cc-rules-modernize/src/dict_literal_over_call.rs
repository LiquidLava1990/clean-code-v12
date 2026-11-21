//! `cc.modernize.dict_literal_over_call` — Python `dict(a=1, b=2)`
//! superseded by the literal `{"a": 1, "b": 2}`.
//!
//! Mirrors ruff `C406` (unnecessary-dict-call) and refurb `FURB123`.
//! Detection: any [`NodeKind::Call`] whose canonical callee text is
//! exactly `dict` and whose first-arg / signature property reveals
//! at least one keyword argument (`name=value`) with no positional
//! seed argument.
//!
//! Severity: `Nit` — both forms produce identical dicts; the literal
//! is faster (skips a function call) and reads as data instead of
//! code.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.dict_literal_over_call`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DictLiteralOverCallRule;

const ARG_KEYS: &[&str] = &["args", "signature", "arguments", "call_text"];

impl Rule for DictLiteralOverCallRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.dict_literal_over_call"
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
        "Python `dict(a=1, b=2)` superseded by `{\"a\": 1, \"b\": 2}`"
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
    if !is_dict_callee(&text) {
        return None;
    }
    let args = collected_args(ctx, id)?;
    if !looks_like_kwargs_only(&args) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !path.as_str().ends_with(".py") {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.dict_literal_over_call",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: "`dict(...)` with kw-args superseded by `{}` literal".into(),
        explanation: "`dict(a=1, b=2)` calls a constructor which has to \
             unpack the kwargs, allocate a `dict`, and copy each entry. \
             The `{\"a\": 1, \"b\": 2}` literal builds the same dict in \
             one bytecode instruction (`BUILD_MAP`), reads as data, and \
             allows non-identifier keys without quoting tricks."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `dict(a=1, b=2)` with `{\"a\": 1, \"b\": 2}`. Keep the \
             call form only when copying from another mapping (`dict(other)`) \
             or when one of the keys is not a valid Python identifier."
                .into(),
        ),
        snippet: format!("dict({args})"),
        weight: 1,
    }))
}

fn is_dict_callee(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    text == "dict"
        || text.starts_with("dict(")
        || text.starts_with("dict ")
        || text.contains(" dict ")
        || text.contains(" dict(")
}

fn collected_args(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    for key in ARG_KEYS {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn looks_like_kwargs_only(args: &str) -> bool {
    let trimmed = strip_outer_parens(args.trim());
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains("**") {
        return false;
    }
    let mut saw_kwarg = false;
    for piece in split_top_level_commas(trimmed) {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        if !looks_like_keyword_arg(piece) {
            return false;
        }
        saw_kwarg = true;
    }
    saw_kwarg
}

fn strip_outer_parens(s: &str) -> &str {
    s.strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or(s)
}

fn looks_like_keyword_arg(piece: &str) -> bool {
    let Some(eq) = piece.find('=') else {
        return false;
    };
    if piece.as_bytes().get(eq.saturating_sub(1)).copied() == Some(b'!') {
        return false;
    }
    if piece.as_bytes().get(eq + 1).copied() == Some(b'=') {
        return false;
    }
    let name = piece[..eq].trim();
    !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (idx, ch) in s.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}
