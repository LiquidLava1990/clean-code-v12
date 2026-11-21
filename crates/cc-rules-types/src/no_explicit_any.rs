//! `cc.type.no_explicit_any` — declaration-site `: any` annotation on a
//! variable, parameter, or function return type.
//!
//! Syntactic shadow of TypeScript ESLint's `no-explicit-any`. The
//! existing [`crate::no_unsafe_argument`] probe detects USES of `any`
//! (the value flowing across a typed boundary); this probe detects the
//! DECLARATION that introduces the `any` in the first place. They are
//! complementary — the declaration site is the right place to fix the
//! issue, the use site is where the silent failure manifests.
//!
//! Detection:
//! - [`NodeKind::Variable`] with `type` / `type_annotation` == `any`.
//! - [`NodeKind::Parameter`] with `type` / `type_annotation` == `any`.
//! - [`NodeKind::Function`] / [`NodeKind::Method`] with `return_type`
//!   / `type_annotation` == `any`.
//!
//! TypeScript-only (`.ts` / `.tsx`); JavaScript has no `any` literal so
//! the rule degrades to silence there.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-EXPLICIT-ANY.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoExplicitAnyRule;

impl Rule for NoExplicitAnyRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_explicit_any"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "explicit `: any` declaration erases the type system at this boundary"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [
            NodeKind::Variable,
            NodeKind::Parameter,
            NodeKind::Function,
            NodeKind::Method,
        ] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_node(ctx, node.id, kind) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_node(ctx: &RuleContext<'_>, id: NodeId, kind: NodeKind) -> Option<Finding> {
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
    let (annotation_key, surface) = match kind {
        NodeKind::Function | NodeKind::Method => ("return_type", "return type"),
        _ => ("type", "declared type"),
    };
    let annotation = string_prop(ctx.batch, id, annotation_key)
        .or_else(|| string_prop(ctx.batch, id, "type_annotation"))?;
    if annotation.trim() != "any" {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_explicit_any",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("`{name}` declares {surface} as `any`"),
        explanation: format!(
            "Declaring `{name}` as `any` opts out of the TypeScript type \
             system at this boundary. Every downstream check on this value \
             becomes a fiction the compiler will not enforce. Replace with a \
             concrete type, a generic, `unknown` (then narrow), or a union."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace `any` with the actual type. If the type really is open, \
             use `unknown` and narrow with a type guard / runtime validator. \
             If the value is opaque, model it as a sealed nominal type \
             (`type Opaque = string & { __brand: 'opaque' }`)."
                .into(),
        ),
        snippet: annotation.to_owned(),
        weight: 2,
    }))
}

fn is_typescript(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "ts" | "typescript")
}

fn is_ts_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".ts") || lower.ends_with(".tsx")
}
