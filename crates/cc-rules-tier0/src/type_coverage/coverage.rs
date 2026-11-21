//! `cc.type.coverage` — flag public functions whose parameters or
//! return type lack a real annotation.
//!
//! Per-language rules:
//!
//! - Python: missing `:` annotation, or annotation == `Any`.
//! - TypeScript / JavaScript: missing type, or annotation == `any`.
//! - Go: untyped return / parameter, or annotation == `interface{}`.
//! - Rust: 100 % type coverage by definition; rule is a no-op.
//!
//! The rule reads `language` off the enclosing `File` node. Unknown
//! languages are skipped (silent no-op).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{
    ast_children, ast_parent, bool_prop, node_by_id, node_kind, nodes_of_kind, string_prop,
};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

/// Tier-0 forever rule R-TYPE.
#[derive(Debug, Default, Clone, Copy)]
pub struct TypeCoverageRule;

impl Rule for TypeCoverageRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.coverage"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "public function lacks parameter or return type annotation"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let language = function_language(ctx, id)?;
    if matches!(language.as_str(), "rust") {
        return None;
    }
    if !is_public(ctx, id, &language) {
        return None;
    }
    let issues = collect_untyped(ctx, id, &language);
    if issues.is_empty() {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let detail = issues.join(", ");
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.type.coverage",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::certain(),
        location,
        headline: format!("function `{name}` is missing types ({detail})"),
        explanation: format!(
            "Public APIs need annotations. `{name}` ({language}) has unannotated \
             slots: {detail}. Tier-0 requires every public surface to declare its \
             types."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add a precise type to each unannotated slot; never leave `Any` / `any` \
             / `interface{}` on a public boundary."
                .into(),
        ),
        snippet: String::new(),
        weight: u32::try_from(issues.len()).unwrap_or(u32::MAX),
    }))
}

fn function_language(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    let mut cur = id;
    for _ in 0..256_u16 {
        if node_kind(ctx.batch, cur) == Some(NodeKind::File) {
            return string_prop(ctx.batch, cur, "language").map(str::to_owned);
        }
        cur = ast_parent(ctx.batch, cur)?;
    }
    None
}

fn is_public(ctx: &RuleContext<'_>, id: NodeId, language: &str) -> bool {
    if bool_prop(ctx.batch, id, "is_pub").unwrap_or(false)
        || bool_prop(ctx.batch, id, "is_export").unwrap_or(false)
    {
        return true;
    }
    if matches!(string_prop(ctx.batch, id, "visibility"), Some("public")) {
        return true;
    }
    // Language defaults: Python / TS treat top-level symbols as public
    // unless explicitly underscored. Go uses Capital initial.
    let name = string_prop(ctx.batch, id, "name").unwrap_or("");
    match language {
        "go" => name.chars().next().is_some_and(|c| c.is_ascii_uppercase()),
        "python" | "py" | "typescript" | "ts" | "javascript" | "js" => !name.starts_with('_'),
        _ => false,
    }
}

fn collect_untyped(ctx: &RuleContext<'_>, id: NodeId, language: &str) -> Vec<String> {
    let mut issues: Vec<String> = Vec::new();
    for child in ast_children(ctx.batch, id) {
        if node_kind(ctx.batch, child) != Some(NodeKind::Parameter) {
            continue;
        }
        let pname = string_prop(ctx.batch, child, "name").unwrap_or("<param>");
        if matches!(pname, "self" | "cls" | "this") {
            continue;
        }
        if param_is_untyped(ctx, child, language) {
            issues.push(format!("param `{pname}`"));
        }
    }
    if return_is_untyped(ctx, id, language) {
        issues.push("return".to_owned());
    }
    issues
}

fn param_is_untyped(ctx: &RuleContext<'_>, id: NodeId, language: &str) -> bool {
    let raw = string_prop(ctx.batch, id, "type");
    is_missing_or_any(raw, language)
}

fn return_is_untyped(ctx: &RuleContext<'_>, id: NodeId, language: &str) -> bool {
    if let Some(node) = node_by_id(ctx.batch, id) {
        if let Some(cc_cpg::Value::String(s)) = node.prop("return_type") {
            return is_missing_or_any(Some(s.as_str()), language);
        }
    }
    is_missing_or_any(None, language)
}

fn is_missing_or_any(raw: Option<&str>, language: &str) -> bool {
    match raw {
        None => true,
        Some(t) => {
            let trimmed = t.trim();
            if trimmed.is_empty() {
                return true;
            }
            match language {
                "go" => trimmed == "interface{}" || trimmed == "any",
                "python" | "py" => trimmed == "Any" || trimmed == "typing.Any",
                _ => trimmed == "any",
            }
        }
    }
}
