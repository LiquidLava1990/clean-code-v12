//! `cc.modernize.list_call_in_set_call` — Python `set(list(x))`,
//! `set(tuple(x))`, `list(list(x))`, and similar redundant-builder
//! calls.
//!
//! Mirrors ruff `PERF101` and refurb `FURB168`. Detection: any
//! [`NodeKind::Call`] whose canonical callee text contains a
//! redundant outer/inner pair such as `set(list(`, `list(tuple(`,
//! `set(set(`, etc.
//!
//! Severity: `Nit` — both forms produce identical results; the inner
//! builder is just an allocation that the outer constructor
//! immediately throws away.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.list_call_in_set_call`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ListCallInSetCallRule;

const TEXT_KEYS: &[&str] = &["signature", "args", "call_text", "expression"];

/// Pairs of (outer-builder, inner-builder) where the inner builder is
/// thrown away by the outer one. Each pair is searched as the literal
/// substring `outer(inner(`.
const REDUNDANT_PAIRS: &[(&str, &str)] = &[
    ("set", "list"),
    ("set", "tuple"),
    ("set", "set"),
    ("list", "list"),
    ("list", "tuple"),
    ("tuple", "list"),
    ("tuple", "tuple"),
    ("frozenset", "list"),
    ("frozenset", "set"),
];

impl Rule for ListCallInSetCallRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.list_call_in_set_call"
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
        "Python `set(list(x))` / `list(tuple(x))` superseded by single call"
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
    let haystack = build_haystack(ctx, id);
    if haystack.is_empty() {
        return None;
    }
    let (outer, inner) = first_redundant_pair(&haystack)?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !path.as_str().ends_with(".py") {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.list_call_in_set_call",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{outer}({inner}(...))` builds an intermediate it discards"),
        explanation: format!(
            "`{outer}({inner}(x))` materialises an intermediate `{inner}` \
             only to feed it to the `{outer}` constructor, which iterates \
             over it once and throws it away. `{outer}(x)` consumes the \
             same iterable directly with one allocation instead of two."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace `{outer}({inner}(x))` with `{outer}(x)`. Both spellings \
             accept any iterable, so the rewrite is safe whenever `x` is \
             not consumed by other code."
        )),
        snippet: haystack,
        weight: 1,
    }))
}

fn build_haystack(ctx: &RuleContext<'_>, id: NodeId) -> String {
    let mut out = callee_text(ctx.batch, id);
    for key in TEXT_KEYS {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(value);
        }
    }
    out
}

fn first_redundant_pair(haystack: &str) -> Option<(&'static str, &'static str)> {
    for (outer, inner) in REDUNDANT_PAIRS {
        let needle = format!("{outer}({inner}(");
        if haystack.contains(&needle) {
            return Some((*outer, *inner));
        }
    }
    None
}
