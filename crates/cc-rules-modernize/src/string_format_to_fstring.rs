//! `cc.modernize.string_format_to_fstring` — Python `"...".format(...)`
//! superseded by f-strings.
//!
//! Mirrors ruff `UP032` (use-fstring). Sibling to the narrower
//! `cc.modernize.string_format_legacy` probe which handles printf-style
//! `%` formatting (ruff `UP031`).
//!
//! Detection: any [`NodeKind::Call`] whose canonical callee text
//! contains `.format(` and whose receiver looks like a string literal
//! (`"…".format(`, `'…'.format(`, triple-quoted variants), or whose
//! callee text is the bound-method form `str.format`.
//!
//! Severity: `Nit` — the rewrite is mechanical and stylistic; both
//! forms produce identical strings.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.string_format_to_fstring`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StringFormatToFstringRule;

const TEXT_KEYS: &[&str] = &["text", "expression", "signature", "value"];

const FORMAT_NEEDLES: &[&str] = &[
    "\".format(",
    "'.format(",
    "\"\"\".format(",
    "'''.format(",
    "str.format",
];

impl Rule for StringFormatToFstringRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.string_format_to_fstring"
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
        "Python `\"...\".format(...)` superseded by f-strings"
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
    if !FORMAT_NEEDLES.iter().any(|n| haystack.contains(n)) {
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
        rule_id: "cc.modernize.string_format_to_fstring",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: "`\"…\".format(…)` superseded by f-string".into(),
        explanation: "`str.format` evaluates each placeholder by name or \
             positional index, allocates an `Arguments` object per call, \
             and hides the substituted expressions one level away from \
             the literal. Python 3.6+ f-strings inline the expressions at \
             the call site, evaluate ~2x faster, and let editors / type \
             checkers see the names directly."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `\"{} {}\".format(a, b)` with `f\"{a} {b}\"`. Format \
             specifiers carry over: `\"{:.2f}\".format(x)` becomes \
             `f\"{x:.2f}\"`."
                .into(),
        ),
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
