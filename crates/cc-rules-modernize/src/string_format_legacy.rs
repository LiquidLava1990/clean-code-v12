//! `cc.modernize.string_format_legacy` — Python printf-style
//! `"%s" % x` superseded by f-strings.
//!
//! Mirrors ruff `UP031` (printf-style formatting). The disjoint
//! `.format()` form is handled by the Phase-8 sibling probe
//! `cc.modernize.string_format_to_fstring` (ruff `UP032`).
//!
//! Detection looks at [`NodeKind::Call`] / [`NodeKind::Read`] /
//! [`NodeKind::Write`] nodes whose canonical text reveals a `%`
//! formatting expression — a quoted string literal followed by the
//! `%` operator and a value or tuple.
//!
//! Severity: `Required` — superseded by f-strings since Python 3.6.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.string_format_legacy`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StringFormatLegacyRule;

const TEXT_KEYS: &[&str] = &["text", "expression", "signature", "value"];

/// Substrings that uniquely identify a printf-style `%`-format
/// expression. The leading-quote needles avoid matching the `%`
/// modulo operator on numeric values.
const PERCENT_NEEDLES: &[&str] = &[
    "\" % ", "' % ", "\"%s\"", "'%s'", "\"%d\"", "'%d'", "\"%r\"", "'%r'", "\"%f\"", "'%f'",
];

impl Rule for StringFormatLegacyRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.string_format_legacy"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "Python printf-style `\"%s\" % x` superseded by f-strings"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Call, NodeKind::Read, NodeKind::Write] {
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
    let haystack = build_haystack(ctx, id);
    if haystack.is_empty() {
        return None;
    }
    if !PERCENT_NEEDLES.iter().any(|n| haystack.contains(n)) {
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
        rule_id: "cc.modernize.string_format_legacy",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: "Printf-style `\"%s\" % x` superseded by f-strings".into(),
        explanation: "Python 3.6+ f-strings (`f\"...{value}...\"`) inline expressions \
             at the call site, evaluate ~2x faster than `\"%s\" % …`, and \
             surface formatting bugs at parse time instead of runtime. \
             `.format()` is handled by the sibling \
             `cc.modernize.string_format_to_fstring` probe."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `\"%s\" % value` with `f\"{value}\"`. Multi-arg \
             `\"%s %s\" % (a, b)` becomes `f\"{a} {b}\"`."
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
