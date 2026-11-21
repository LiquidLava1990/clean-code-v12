//! `cc.modernize.deprecated_typing_alias` — Python `typing.List` / `Dict`
//! superseded by builtin generics on 3.9+.
//!
//! Mirrors ruff `UP006` (use builtin generics) + `UP035` (deprecated
//! import). Detection scans [`NodeKind::Identifier`] / [`NodeKind::Type`]
//! / [`NodeKind::Import`] nodes for any of the legacy aliases listed in
//! [`crate::helpers::LEGACY_TYPING_ALIASES`].
//!
//! Severity: `Required` — `typing.List[int]` is officially deprecated
//! and slated for removal.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint, LEGACY_TYPING_ALIASES,
};

/// Family-26 probe `cc.modernize.deprecated_typing_alias`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeprecatedTypingAliasRule;

const NAME_KEYS: &[&str] = &["qualified", "name", "annotation", "value", "module"];

impl Rule for DeprecatedTypingAliasRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.deprecated_typing_alias"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Python `typing.List`/`Dict`/etc. superseded by builtin generics"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Identifier, NodeKind::Type, NodeKind::Import] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_node(ctx, node) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_node(ctx: &RuleContext<'_>, node: &Node) -> Option<Finding> {
    let (legacy, replacement) = first_alias_match(ctx, node.id)?;
    let path = enclosing_file_path(ctx.batch, node.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !path.as_str().ends_with(".py") {
        return None;
    }
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.deprecated_typing_alias",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`{legacy}` is deprecated; use `{replacement}`"),
        explanation: format!(
            "`{legacy}` was retained only for back-compatibility with Python \
             3.8. From 3.9 onward, `{replacement}` is the canonical form and \
             `{legacy}` raises `DeprecationWarning` ahead of removal in a \
             future release."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace `{legacy}` with `{replacement}` and drop the matching \
             `from typing import …` if no other alias is needed."
        )),
        snippet: legacy.to_owned(),
        weight: 1,
    }))
}

fn first_alias_match(ctx: &RuleContext<'_>, id: NodeId) -> Option<(&'static str, &'static str)> {
    for key in NAME_KEYS {
        let Some(value) = string_prop(ctx.batch, id, key) else {
            continue;
        };
        for &(legacy, replacement) in LEGACY_TYPING_ALIASES {
            if value == legacy || value.contains(legacy) {
                return Some((legacy, replacement));
            }
        }
    }
    None
}
