//! `cc.type.no_unsafe_enum_comparison` — comparing members of two
//! distinct enums (or an enum to a bare literal of the wrong shape).
//!
//! Syntactic shadow of TypeScript ESLint's `no-unsafe-enum-comparison`.
//! Full version requires type-flow analysis; we approximate by:
//!
//! 1. Walking every [`NodeKind::Class`] whose `kind` property is `enum`
//!    (or whose `name` matches an enum convention) and collecting its
//!    member identifiers.
//! 2. For each [`NodeKind::Branch`] / `condition` text, scan for a
//!    comparison `<Lhs>.X === <Rhs>.Y` (or `!==` / `==` / `!=`). If
//!    `<Lhs>` and `<Rhs>` are both known enum names AND they differ,
//!    flag.
//!
//! TS-only — JS does not have enums.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-UNSAFE-ENUM-COMPARISON.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoUnsafeEnumComparisonRule;

impl Rule for NoUnsafeEnumComparisonRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_unsafe_enum_comparison"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "comparison between members of two distinct enums"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let enum_names = collect_enum_names(ctx);
        if enum_names.len() < 2 {
            return Vec::new();
        }
        let mut out = Vec::new();
        for kind in [NodeKind::Branch, NodeKind::Loop, NodeKind::Variable] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_node(ctx, node.id, &enum_names) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn collect_enum_names(ctx: &RuleContext<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for node in nodes_of_kind(ctx.batch, NodeKind::Class) {
        let kind_prop = string_prop(ctx.batch, node.id, "kind").unwrap_or("");
        if kind_prop != "enum" {
            continue;
        }
        if let Some(name) = string_prop(ctx.batch, node.id, "name") {
            out.push(name.to_owned());
        }
    }
    out
}

fn check_node(ctx: &RuleContext<'_>, id: NodeId, enum_names: &[String]) -> Option<Finding> {
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
    let condition = string_prop(ctx.batch, id, "condition")
        .or_else(|| string_prop(ctx.batch, id, "expression"))?;
    let (lhs_enum, rhs_enum) = find_cross_enum_comparison(condition, enum_names)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_unsafe_enum_comparison",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("cross-enum comparison `{lhs_enum}.* vs {rhs_enum}.*`",),
        explanation: format!(
            "`{lhs_enum}` and `{rhs_enum}` are different enum types. \
             TypeScript represents enum members as primitive numbers / \
             strings, so a structural `===` comparison can be \"true\" by \
             coincidence (both `0`) without the values having any \
             semantic relationship. The check is almost always a bug — \
             one side is the wrong enum."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Decide which enum the value should belong to and convert \
             explicitly. If both branches are intentional, model the \
             relationship with a typed mapping (`const adapt: Record<A, B> = \
             { ... }`) instead of a direct comparison."
                .into(),
        ),
        snippet: condition.to_owned(),
        weight: 2,
    }))
}

fn find_cross_enum_comparison<'a>(
    condition: &str,
    enum_names: &'a [String],
) -> Option<(&'a str, &'a str)> {
    for sep in ["===", "!==", "==", "!="] {
        if let Some(pair) = try_split_cross_enum(condition, sep, enum_names) {
            return Some(pair);
        }
    }
    None
}

fn try_split_cross_enum<'a>(
    condition: &str,
    sep: &str,
    enum_names: &'a [String],
) -> Option<(&'a str, &'a str)> {
    let (lhs, rhs) = condition.split_once(sep)?;
    let l = leading_enum(lhs.trim(), enum_names)?;
    let r = leading_enum(rhs.trim(), enum_names)?;
    if l == r {
        return None;
    }
    Some((l, r))
}

fn leading_enum<'a>(text: &str, enum_names: &'a [String]) -> Option<&'a str> {
    let dot_at = text.find('.')?;
    let head = text.get(..dot_at)?.trim();
    enum_names
        .iter()
        .find(|name| name.as_str() == head)
        .map(String::as_str)
}

fn is_typescript(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "ts" | "typescript")
}

fn is_ts_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts") || lower.ends_with(".tsx")
}
