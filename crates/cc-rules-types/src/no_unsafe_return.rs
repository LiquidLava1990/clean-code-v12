//! `cc.type.no_unsafe_return` — function returns an `any`-typed value
//! while declaring a concrete return type.
//!
//! Syntactic shadow of TypeScript ESLint's `no-unsafe-return`; full
//! version requires type-flow analysis. We approximate via the
//! frontend's per-function `return_expressions` property (a string
//! holding every return-statement expression text, joined by `\n`).
//! When the function declares a concrete return type AND any return
//! expression is either:
//!
//! - a literal `as any` cast (`return x as any;`)
//! - the bare name of a variable previously declared `: any`
//!
//! the rule fires.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-UNSAFE-RETURN.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoUnsafeReturnRule;

impl Rule for NoUnsafeReturnRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_unsafe_return"
    }
    fn category(&self) -> Category {
        Category::Type
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "function declares a concrete return type but returns an `any`-typed value"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        let any_locals = collect_any_locals(ctx);
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id, &any_locals) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn collect_any_locals(ctx: &RuleContext<'_>) -> Vec<String> {
    let mut names = Vec::new();
    for node in nodes_of_kind(ctx.batch, NodeKind::Variable) {
        let Some(name) = string_prop(ctx.batch, node.id, "name") else {
            continue;
        };
        let annotation = string_prop(ctx.batch, node.id, "type")
            .or_else(|| string_prop(ctx.batch, node.id, "type_annotation"))
            .unwrap_or("");
        if annotation.trim() == "any" {
            names.push(name.to_owned());
        }
    }
    names
}

fn check_function(ctx: &RuleContext<'_>, fn_id: NodeId, any_locals: &[String]) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, fn_id)?;
    if !is_typescript(&language) {
        return None;
    }
    let return_type = string_prop(ctx.batch, fn_id, "return_type")?;
    if !is_concrete_return_type(return_type) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, fn_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let return_expressions = string_prop(ctx.batch, fn_id, "return_expressions")?;
    let trigger = classify_returns(return_expressions, any_locals)?;
    let name = string_prop(ctx.batch, fn_id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_unsafe_return",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "`{name}` returns `any` despite declared return type `{return_type}` ({trigger})"
        ),
        explanation: format!(
            "`{name}` declares it returns `{return_type}` but actually \
             returns an `any`-typed value via {trigger}. Callers will trust \
             the declared type and silently wire untyped data into typed \
             code paths."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Validate / narrow the value before returning: a runtime guard \
             (`if (!isUser(x)) throw ...`), a parser (`UserSchema.parse(x)`), \
             or an explicit cast to the declared return type only after \
             shape verification."
                .into(),
        ),
        snippet: return_expressions.to_owned(),
        weight: 3,
    }))
}

fn is_typescript(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "ts" | "typescript")
}

fn is_concrete_return_type(return_type: &str) -> bool {
    let trimmed = return_type.trim();
    !trimmed.is_empty()
        && trimmed != "any"
        && trimmed != "unknown"
        && trimmed != "void"
        && trimmed != "never"
}

fn classify_returns(returns: &str, any_locals: &[String]) -> Option<&'static str> {
    for line in returns.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches("return ")
            .trim_end_matches(';')
            .trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("as any") {
            return Some("`as any` cast");
        }
        for name in any_locals {
            if mentions_identifier(trimmed, name) {
                return Some("`: any`-typed local");
            }
        }
    }
    None
}

fn mentions_identifier(haystack: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|seg| seg == name)
}
