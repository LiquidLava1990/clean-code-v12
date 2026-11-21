//! `cc.type.no_unsafe_argument` — `any`-typed argument flowing into a
//! concretely-typed parameter.
//!
//! Syntactic shadow of TypeScript ESLint's `no-unsafe-argument`; full
//! version requires type-flow analysis. We approximate via two
//! detectable patterns:
//!
//! - The call site argument text contains a literal `as any` cast
//!   (`fn(payload as any)`). Frontends record the argument list on the
//!   `arguments` string property of [`NodeKind::Call`].
//! - A variable declared with explicit `: any` annotation is then
//!   passed unchanged. We detect the declaration via the variable's
//!   `type` property and the use via the call's `arguments` text.
//!
//! Restricted to `ts` / `typescript`. JavaScript has no `any` literal
//! so the rule degrades to silence there.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{callee_text, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-UNSAFE-ARGUMENT.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoUnsafeArgumentRule;

impl Rule for NoUnsafeArgumentRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_unsafe_argument"
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
        "argument carries `any` (via `as any` cast or `: any` declaration) into a typed parameter"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        let any_locals = collect_any_locals(ctx);
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id, &any_locals) {
                out.push(finding);
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

fn check_call(ctx: &RuleContext<'_>, call_id: NodeId, any_locals: &[String]) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, call_id)?;
    if !is_typescript(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, call_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let arguments = string_prop(ctx.batch, call_id, "arguments")?;
    let trigger = classify_argument(arguments, any_locals)?;
    let callee = callee_text(ctx.batch, call_id);
    let location = location_from_node(ctx.batch, call_id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_unsafe_argument",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("call to `{callee}` passes `any` argument ({trigger})"),
        explanation: format!(
            "The call site to `{callee}` smuggles `any` into a typed \
             parameter via {trigger}. This erases every downstream type \
             check at the boundary; the parameter's nominal type becomes \
             a fiction the compiler will not enforce."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Narrow the `any` value with a type guard, a runtime validator \
             (`zod.parse(...)` / `io-ts decode`), or a cast to the actual \
             parameter type after asserting shape. Never widen the parameter \
             to `any` to silence the warning."
                .into(),
        ),
        snippet: arguments.to_owned(),
        weight: 2,
    }))
}

fn is_typescript(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "ts" | "typescript")
}

fn classify_argument(arguments: &str, any_locals: &[String]) -> Option<&'static str> {
    if arguments.contains("as any") {
        return Some("`as any` cast");
    }
    for name in any_locals {
        if mentions_identifier(arguments, name) {
            return Some("`: any`-typed local");
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
