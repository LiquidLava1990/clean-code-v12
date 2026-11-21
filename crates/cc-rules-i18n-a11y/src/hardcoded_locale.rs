//! `cc.i18n.hardcoded_locale` — locale string baked into source.
//!
//! Heuristic: walk every [`NodeKind::Literal`] string; flag any value
//! that contains one of the canonical locale tags (`en_US`, `en-US`,
//! `fr_FR`, `de_DE`, `ja_JP`, `zh_CN`, `pt_BR`) or canonical IANA
//! timezone identifiers (`Europe/Paris`, `America/New_York`). Skips
//! test files and the rule-pack's own source so the
//! [`crate::helpers::LOCALE_PATTERN_TABLE`] does not self-flag.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, I18nA11yFindingBlueprint, LOCALE_PATTERN_TABLE,
};

/// Family-15 probe R-I18N-HARDCODED-LOCALE.
#[derive(Debug, Default, Clone, Copy)]
pub struct HardcodedLocaleRule;

impl Rule for HardcodedLocaleRule {
    fn rule_id(&self) -> &'static str {
        "cc.i18n.hardcoded_locale"
    }
    fn category(&self) -> Category {
        Category::I18n
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "locale identifier baked into a string literal"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Literal) {
            if let Some(finding) = check_literal(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_literal(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let value = string_prop(ctx.batch, id, "value")?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let needle = LOCALE_PATTERN_TABLE.iter().find(|p| value.contains(*p))?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(I18nA11yFindingBlueprint {
        rule_id: "cc.i18n.hardcoded_locale",
        category: Category::I18n,
        severity: Severity::Nit,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("locale identifier `{needle}` is hard-coded in source"),
        explanation: format!(
            "The string `{needle}` pins this code path to a single locale. \
             Localised UIs need the locale to come from the user's session / \
             accept-language header / configuration — never the source. \
             Hard-coded locales also block translation pipelines that key on \
             a single source-of-truth locale tag."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Resolve the locale at runtime from the user session, the \
             `Accept-Language` header, or a config layer. Reserve hard-coded \
             locale tags for tests and translation-bundle filenames."
                .into(),
        ),
        snippet: (*needle).to_owned(),
        weight: 1,
    }))
}
