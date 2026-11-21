//! `cc.modernize.deprecated_unittest_aliases` — Python `unittest`
//! deprecated assertion aliases (`assertEquals`, `assertNotEquals`,
//! `failUnless`, `failIf`, `assertRaisesRegexp`, `assertRegexpMatches`).
//!
//! Mirrors ruff `PT009` and the broader `PT*` family for unittest
//! migrations. Detection: any [`NodeKind::Call`] whose canonical
//! callee text matches one of the deprecated alias names.
//!
//! Severity: `Nit` — the deprecated names still work in current
//! Python, but Python 3.12 fired `DeprecationWarning` on every
//! invocation and a future release is slated to remove them.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.deprecated_unittest_aliases`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeprecatedUnittestAliasesRule;

/// Pairs of (deprecated-alias, modern-replacement). Ordered roughly
/// by frequency in `unittest` migrations.
const DEPRECATED_ALIASES: &[(&str, &str)] = &[
    ("assertEquals", "assertEqual"),
    ("assertNotEquals", "assertNotEqual"),
    ("assertAlmostEquals", "assertAlmostEqual"),
    ("assertNotAlmostEquals", "assertNotAlmostEqual"),
    ("assert_", "assertTrue"),
    ("failUnless", "assertTrue"),
    ("failIf", "assertFalse"),
    ("failUnlessEqual", "assertEqual"),
    ("failIfEqual", "assertNotEqual"),
    ("failUnlessAlmostEqual", "assertAlmostEqual"),
    ("failIfAlmostEqual", "assertNotAlmostEqual"),
    ("failUnlessRaises", "assertRaises"),
    ("assertRaisesRegexp", "assertRaisesRegex"),
    ("assertRegexpMatches", "assertRegex"),
    ("assertNotRegexpMatches", "assertNotRegex"),
];

impl Rule for DeprecatedUnittestAliasesRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.deprecated_unittest_aliases"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "Python `unittest` deprecated assertion aliases (PT009)"
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
    if text.is_empty() {
        return None;
    }
    let (deprecated, replacement) = first_deprecated_match(&text)?;
    let path = enclosing_file_path(ctx.batch, id)?;
    // Test files are exactly where unittest aliases live, so we do
    // NOT skip them. We do still skip the rule-pack source itself.
    if looks_like_rule_pack_source(&path) {
        return None;
    }
    if !path.as_str().ends_with(".py") {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.deprecated_unittest_aliases",
        severity: Severity::Nit,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("`{deprecated}` is deprecated; use `{replacement}`"),
        explanation: format!(
            "`unittest.TestCase.{deprecated}` is a deprecated alias for \
             `{replacement}`. Python 3.12 fires `DeprecationWarning` on \
             every call, and the names are scheduled for removal in a \
             future release per PEP-3151."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace `self.{deprecated}(…)` with `self.{replacement}(…)`. \
             The argument shape is identical."
        )),
        snippet: text,
        weight: 1,
    }))
}

fn first_deprecated_match(text: &str) -> Option<(&'static str, &'static str)> {
    DEPRECATED_ALIASES
        .iter()
        .find(|(alias, _)| matches_alias(text, alias))
        .map(|(alias, replacement)| (*alias, *replacement))
}

fn matches_alias(text: &str, alias: &str) -> bool {
    if text == alias {
        return true;
    }
    let dot_form = format!(".{alias}");
    if text.contains(&dot_form) {
        return true;
    }
    let paren_form = format!("{alias}(");
    text.contains(&paren_form)
}
