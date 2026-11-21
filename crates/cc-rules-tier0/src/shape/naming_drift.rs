//! `cc.shape.naming_drift` — flag identifiers that violate the
//! per-language convention.
//!
//! Phase-1 rules:
//!
//! | Language | Function / Variable | Class / Type |
//! |----------|---------------------|--------------|
//! | python   | `snake_case`        | `PascalCase` |
//! | rust     | `snake_case`        | `PascalCase` |
//! | go (exp) | `MixedCaps`         | `MixedCaps`  |
//! | go (loc) | `mixedCaps`         | `mixedCaps`  |
//! | ts / js  | `camelCase`         | `PascalCase` |
//!
//! Names < 3 chars are skipped (loop counters, common abbreviations).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

const MIN_NAME_LEN: usize = 3;

/// Tier-0 forever rule R-NAME.
#[derive(Debug, Default, Clone, Copy)]
pub struct NamingDriftRule;

impl Rule for NamingDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.naming_drift"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "identifier violates the per-language naming convention"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [
            NodeKind::Function,
            NodeKind::Method,
            NodeKind::Class,
            NodeKind::Variable,
            NodeKind::Parameter,
        ] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_name(ctx, node.id, kind) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_name(ctx: &RuleContext<'_>, id: NodeId, kind: NodeKind) -> Option<Finding> {
    let name = string_prop(ctx.batch, id, "name")?;
    if name.len() < MIN_NAME_LEN {
        return None;
    }
    if name.starts_with('_') {
        // Private / dunder / discard — convention is opt-out, not drift.
        return None;
    }
    let language = enclosing_language(ctx, id)?;
    let expected = expected_convention(&language, kind, ctx, id);
    if matches_convention(name, expected) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.naming_drift",
        category: Category::Shape,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "identifier `{name}` is not {} ({language})",
            expected.label()
        ),
        explanation: format!(
            "Naming drift confuses readers. Identifier `{name}` ({language}, \
             {kind:?}) does not match the project's expected {} convention.",
            expected.label()
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Rename `{name}` to {} form to match the rest of the codebase.",
            expected.label()
        )),
        snippet: String::new(),
        weight: 1,
    }))
}

#[derive(Debug, Clone, Copy)]
enum Convention {
    Snake,
    Pascal,
    Camel,
    GoExportedMixed,
    GoLocalMixed,
}

impl Convention {
    const fn label(self) -> &'static str {
        match self {
            Self::Snake => "snake_case",
            Self::Pascal => "PascalCase",
            Self::Camel => "camelCase",
            Self::GoExportedMixed => "MixedCaps",
            Self::GoLocalMixed => "mixedCaps",
        }
    }
}

fn enclosing_language(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    let mut cur = id;
    for _ in 0..256_u16 {
        if node_kind(ctx.batch, cur) == Some(NodeKind::File) {
            return string_prop(ctx.batch, cur, "language").map(str::to_owned);
        }
        cur = ast_parent(ctx.batch, cur)?;
    }
    None
}

fn expected_convention(
    language: &str,
    kind: NodeKind,
    ctx: &RuleContext<'_>,
    id: NodeId,
) -> Convention {
    match language {
        "python" | "py" | "rust" => match kind {
            NodeKind::Class => Convention::Pascal,
            _ => Convention::Snake,
        },
        "go" => {
            // Capital initial = exported, treat as MixedCaps; otherwise mixedCaps.
            let name = string_prop(ctx.batch, id, "name").unwrap_or("");
            if name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                Convention::GoExportedMixed
            } else {
                Convention::GoLocalMixed
            }
        }
        "typescript" | "ts" | "javascript" | "js" => match kind {
            NodeKind::Class => Convention::Pascal,
            _ => Convention::Camel,
        },
        _ => Convention::Snake,
    }
}

fn matches_convention(name: &str, conv: Convention) -> bool {
    match conv {
        Convention::Snake => is_snake_case(name),
        Convention::Pascal => is_pascal_case(name),
        Convention::Camel | Convention::GoLocalMixed => is_camel_case(name),
        Convention::GoExportedMixed => is_pascal_case(name) || is_camel_case(name),
    }
}

fn is_snake_case(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn is_pascal_case(name: &str) -> bool {
    let first = name.chars().next();
    if !first.is_some_and(|c| c.is_ascii_uppercase()) {
        return false;
    }
    !name.contains('_')
}

fn is_camel_case(name: &str) -> bool {
    let first = name.chars().next();
    if !first.is_some_and(|c| c.is_ascii_lowercase()) {
        return false;
    }
    !name.contains('_')
}
