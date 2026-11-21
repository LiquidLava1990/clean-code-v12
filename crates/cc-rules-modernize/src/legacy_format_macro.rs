//! `cc.modernize.legacy_format_macro` — Rust `format!("{}", x)` whose
//! template is the literal `"{}"` and whose argument is a single value
//! that already implements `Display`.
//!
//! Mirrors clippy `useless_format`. Detection: a [`NodeKind::Call`] whose
//! callee text matches `format!` and whose `template` / `signature`
//! property contains the bare `"{}"` placeholder with no further
//! formatting directives.
//!
//! Severity: `Nit` — substitute `.to_string()` to skip allocation of a
//! transient `Arguments` struct.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.legacy_format_macro`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LegacyFormatMacroRule;

impl Rule for LegacyFormatMacroRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.legacy_format_macro"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "Rust `format!(\"{}\", x)` superseded by `.to_string()`"
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
    if !looks_like_format_macro(&text) {
        return None;
    }
    if !template_is_bare_placeholder(ctx, id, &text) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if !path.as_str().ends_with(".rs") {
        return None;
    }
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.legacy_format_macro",
        severity: Severity::Nit,
        confidence: Confidence::new(0.7),
        location,
        headline: "`format!(\"{}\", x)` is just `x.to_string()`".into(),
        explanation: "`format!` allocates an `Arguments` struct, walks the \
             format spec, and finally writes through a `String` builder. \
             For a bare `\"{}\"` placeholder over a single Display value, \
             `.to_string()` is the same allocation minus the formatter \
             machinery."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `format!(\"{}\", x)` with `x.to_string()`. If `x` is \
             already a `String`, replace with `x.clone()`."
                .into(),
        ),
        snippet: text,
        weight: 1,
    }))
}

fn looks_like_format_macro(text: &str) -> bool {
    text.contains("format!") || text.starts_with("format !") || text.ends_with("format")
}

fn template_is_bare_placeholder(ctx: &RuleContext<'_>, id: NodeId, callee: &str) -> bool {
    for key in ["template", "first_arg", "signature", "macro_args"] {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            if has_bare_placeholder(value) {
                return true;
            }
        }
    }
    has_bare_placeholder(callee)
}

fn has_bare_placeholder(s: &str) -> bool {
    s.contains("\"{}\"") || s.contains("'{}'")
}
