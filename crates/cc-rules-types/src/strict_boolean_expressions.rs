//! `cc.type.strict_boolean_expressions` — implicit truthy/falsy use of
//! a string- or number-typed value in a boolean position.
//!
//! Syntactic shadow of TypeScript ESLint's `strict-boolean-expressions`.
//! Full version requires type-flow analysis; we approximate by:
//!
//! - Collect locals declared with `: string` or `: number` (or
//!   `: string | number`).
//! - For each [`NodeKind::Branch`] / [`NodeKind::Loop`] whose
//!   `condition` is exactly the bare identifier of one of those locals,
//!   flag.
//!
//! `if (str.length > 0)` / `if (n !== 0)` are silent — explicit
//! comparisons fall through. `if (str)` / `while (n)` are flagged.
//!
//! TS/JS-only.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-STRICT-BOOLEAN-EXPRESSIONS.
#[derive(Debug, Default, Clone, Copy)]
pub struct StrictBooleanExpressionsRule;

impl Rule for StrictBooleanExpressionsRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.strict_boolean_expressions"
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
        "string / number used as bare boolean condition — should be explicit comparison"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let typed_locals = collect_typed_locals(ctx);
        if typed_locals.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for kind in [NodeKind::Branch, NodeKind::Loop] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_branch(ctx, node.id, &typed_locals) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
struct TypedLocal {
    name: String,
    kind: TypedKind,
}

#[derive(Debug, Clone, Copy)]
enum TypedKind {
    String,
    Number,
    StringOrNumber,
}

impl TypedKind {
    const fn label(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::StringOrNumber => "string | number",
        }
    }
    const fn fix_hint(self) -> &'static str {
        match self {
            Self::String => "compare explicitly: `if (x.length > 0)` or `if (x !== \"\")`",
            Self::Number => "compare explicitly: `if (x !== 0)` or `if (Number.isFinite(x))`",
            Self::StringOrNumber => {
                "split the union and compare each branch explicitly — bare \
                 truthy on `string | number` flips on `0` and `\"\"` together"
            }
        }
    }
}

fn collect_typed_locals(ctx: &RuleContext<'_>) -> Vec<TypedLocal> {
    let mut out = Vec::new();
    for node in nodes_of_kind(ctx.batch, NodeKind::Variable) {
        let Some(name) = string_prop(ctx.batch, node.id, "name") else {
            continue;
        };
        let annotation = string_prop(ctx.batch, node.id, "type")
            .or_else(|| string_prop(ctx.batch, node.id, "type_annotation"))
            .unwrap_or("")
            .trim();
        let Some(kind) = classify_annotation(annotation) else {
            continue;
        };
        out.push(TypedLocal {
            name: name.to_owned(),
            kind,
        });
    }
    out
}

fn classify_annotation(annotation: &str) -> Option<TypedKind> {
    match annotation {
        "string" => Some(TypedKind::String),
        "number" => Some(TypedKind::Number),
        "string | number" | "number | string" => Some(TypedKind::StringOrNumber),
        _ => None,
    }
}

fn check_branch(ctx: &RuleContext<'_>, id: NodeId, typed_locals: &[TypedLocal]) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, id)?;
    if !is_ts_or_js(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if !is_ts_or_js_extension(path.as_str()) {
        return None;
    }
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let condition = string_prop(ctx.batch, id, "condition")?;
    let trimmed = condition.trim();
    let local = typed_locals.iter().find(|l| l.name == trimmed)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.strict_boolean_expressions",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "`if ({trimmed})` reads `{trimmed}: {label}` as a boolean",
            label = local.kind.label(),
        ),
        explanation: format!(
            "`{trimmed}` is declared `{label}`. Implicit truthy on `string` \
             flips on `\"\"` only; on `number` it flips on `0` AND `NaN` \
             together. Both confuse intent: a 0-length string is not the \
             same as a missing string; `0` is not the same as `undefined`. \
             Make the comparison explicit.",
            label = local.kind.label(),
        ),
        remediation: Remediation::SuggestedRewrite(local.kind.fix_hint().to_owned()),
        snippet: condition.to_owned(),
        weight: 1,
    }))
}

fn is_ts_or_js(language: &str) -> bool {
    matches!(
        language.to_ascii_lowercase().as_str(),
        "ts" | "typescript" | "js" | "javascript"
    )
}

fn is_ts_or_js_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts")
        || lower.ends_with(".tsx")
        || lower.ends_with(".js")
        || lower.ends_with(".jsx")
}
