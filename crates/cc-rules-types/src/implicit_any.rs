//! `cc.type.implicit_any` — flag implicit-any annotations on the
//! parameter type or return type of any PUBLIC function or class
//! method.
//!
//! Per-language markers (see [`crate::helpers::IMPLICIT_ANY_TABLE`]):
//!
//! - Python: `Any`, `typing.Any`
//! - TypeScript / JavaScript: `any`
//! - Go: `interface{}`, `any`
//! - Rust: `&dyn Any`, `&mut dyn Any`, `Box<dyn Any>`, `dyn Any`
//!
//! A function is considered public when any of:
//!
//! - `is_pub == true` (Rust-flavoured frontends)
//! - `is_export == true` (TS / JS frontends)
//! - `visibility == "public"` (cross-language explicit)
//! - Language default: top-level Python / TS / JS symbol whose name
//!   does not start with `_`; Go symbol whose name starts with an
//!   ASCII uppercase letter.
//!
//! The rule degrades to silence when the enclosing `File.language` is
//! unknown or absent — this prevents mass-flagging on partial CPGs.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, bool_prop, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_implicit_any,
    location_from_node, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-IMPLICIT-ANY.
#[derive(Debug, Default, Clone, Copy)]
pub struct ImplicitAnyRule;

impl Rule for ImplicitAnyRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.implicit_any"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "public function exposes implicit Any / any / interface{} on a parameter or return type"
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
    let language = enclosing_file_language(ctx.batch, id)?;
    if !is_public(ctx, id, &language) {
        return None;
    }
    let issues = collect_issues(ctx, id, &language);
    if issues.is_empty() {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    let detail = issues.join(", ");
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.implicit_any",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("public `{name}` exposes implicit any ({detail})"),
        explanation: format!(
            "Implicit Any on a public boundary erases every downstream type \
             check. `{name}` ({language}) declares: {detail}. Tier-22 requires \
             a precise nominal type on every public surface."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace `Any` / `any` / `interface{{}}` / `&dyn Any` with a real \
             nominal type, a generic, or a sealed union. If the type really is \
             unknown, lift it to a typed sentinel (`object`, `unknown`, \
             `serde_json::Value`) and document the contract."
                .into(),
        ),
        snippet: String::new(),
        weight: u32::try_from(issues.len()).unwrap_or(u32::MAX),
    }))
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
    let name = string_prop(ctx.batch, id, "name").unwrap_or("");
    public_by_language_default(language, name)
}

fn public_by_language_default(language: &str, name: &str) -> bool {
    let lang = language.to_ascii_lowercase();
    match lang.as_str() {
        "go" => name.chars().next().is_some_and(|c| c.is_ascii_uppercase()),
        "python" | "py" | "typescript" | "ts" | "javascript" | "js" => {
            !name.is_empty() && !name.starts_with('_')
        }
        _ => false,
    }
}

fn collect_issues(ctx: &RuleContext<'_>, id: NodeId, language: &str) -> Vec<String> {
    let mut issues: Vec<String> = Vec::new();
    for child in ast_children(ctx.batch, id) {
        if node_kind(ctx.batch, child) != Some(NodeKind::Parameter) {
            continue;
        }
        let pname = string_prop(ctx.batch, child, "name").unwrap_or("<param>");
        if matches!(pname, "self" | "cls" | "this") {
            continue;
        }
        if let Some(annotation) = read_param_annotation(ctx, child) {
            if is_implicit_any(annotation, language) {
                issues.push(format!("param `{pname}`: `{annotation}`"));
            }
        }
    }
    let return_annotation = string_prop(ctx.batch, id, "return_type")
        .or_else(|| string_prop(ctx.batch, id, "type_annotation"));
    if let Some(annotation) = return_annotation {
        if is_implicit_any(annotation, language) {
            issues.push(format!("return `{annotation}`"));
        }
    }
    issues
}

fn read_param_annotation<'b>(ctx: &RuleContext<'b>, id: NodeId) -> Option<&'b str> {
    string_prop(ctx.batch, id, "type").or_else(|| string_prop(ctx.batch, id, "type_annotation"))
}
