//! `cc.type.no_base_to_string` — string-coercion of a class instance
//! that does not declare its own `toString()` override.
//!
//! Syntactic shadow of TypeScript ESLint's `no-base-to-string`. The
//! default `Object.prototype.toString()` returns `"[object Object]"`,
//! which is rarely what the author intended — usually they meant a
//! property of the instance.
//!
//! Detection in two passes:
//!
//! 1. Walk every [`NodeKind::Class`] in the file. Record its `name` and
//!    whether its `methods_declared` / `members` text contains a
//!    `toString` member.
//! 2. Walk every [`NodeKind::Variable`] with a `type` annotation that
//!    matches a recorded class name without `toString`, then check
//!    every [`NodeKind::Call`] / [`NodeKind::Read`] / [`NodeKind::Write`]
//!    text in the same file for a coercion of that variable:
//!    - `String(<name>)` explicit cast
//!    - `` `${<name>}` `` template interpolation
//!    - `<name> + ""` / `"" + <name>` string concatenation
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

/// Family-22 probe R-TYPE-NO-BASE-TO-STRING.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoBaseToStringRule;

const COERCION_TEXT_KEYS: &[&str] = &["expression", "text", "value", "arguments", "condition"];

impl Rule for NoBaseToStringRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_base_to_string"
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
        "stringifying a class instance with no `toString()` override emits `[object Object]`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let bare_classes = collect_bare_classes(ctx);
        if bare_classes.is_empty() {
            return Vec::new();
        }
        let bare_locals = collect_bare_typed_locals(ctx, &bare_classes);
        if bare_locals.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for kind in [
            NodeKind::Call,
            NodeKind::Read,
            NodeKind::Write,
            NodeKind::Async,
        ] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_node(ctx, node.id, &bare_locals) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn collect_bare_classes(ctx: &RuleContext<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for node in nodes_of_kind(ctx.batch, NodeKind::Class) {
        let Some(name) = string_prop(ctx.batch, node.id, "name") else {
            continue;
        };
        let members = string_prop(ctx.batch, node.id, "methods_declared")
            .or_else(|| string_prop(ctx.batch, node.id, "members"))
            .or_else(|| string_prop(ctx.batch, node.id, "fields_declared"))
            .unwrap_or("");
        if !mentions_to_string(members) {
            out.push(name.to_owned());
        }
    }
    out
}

fn mentions_to_string(haystack: &str) -> bool {
    haystack.contains("toString(") || haystack.contains("toString:")
}

fn collect_bare_typed_locals(
    ctx: &RuleContext<'_>,
    bare_classes: &[String],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for node in nodes_of_kind(ctx.batch, NodeKind::Variable) {
        let Some(name) = string_prop(ctx.batch, node.id, "name") else {
            continue;
        };
        let annotation = string_prop(ctx.batch, node.id, "type")
            .or_else(|| string_prop(ctx.batch, node.id, "type_annotation"))
            .unwrap_or("")
            .trim();
        if annotation.is_empty() {
            continue;
        }
        if let Some(class) = bare_classes.iter().find(|c| c.as_str() == annotation) {
            out.push((name.to_owned(), class.clone()));
        }
    }
    out
}

fn check_node(
    ctx: &RuleContext<'_>,
    id: NodeId,
    bare_locals: &[(String, String)],
) -> Option<Finding> {
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
    let text = first_text_with(ctx, id)?;
    let (local, class) = find_coerced_local(text, bare_locals)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_base_to_string",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("stringifying `{local}: {class}` emits `[object Object]`",),
        explanation: format!(
            "`{local}` is an instance of `{class}` and `{class}` does not \
             override `toString()`. The expression coerces to `[object \
             Object]` at runtime, which is almost never the intent — the \
             usual fix is to access a specific property (`{local}.id`, \
             `{local}.name`) or to define a `toString()` on `{class}`."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Either (a) reach for the specific property you meant — \
             `{local}.id` / `JSON.stringify({local})`, or (b) add a \
             `toString()` method to `{class}` so the coercion has a \
             defined output."
        )),
        snippet: text.to_owned(),
        weight: 1,
    }))
}

fn first_text_with<'b>(ctx: &RuleContext<'b>, id: NodeId) -> Option<&'b str> {
    for key in COERCION_TEXT_KEYS {
        if let Some(text) = string_prop(ctx.batch, id, key) {
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn find_coerced_local<'a>(
    text: &str,
    bare_locals: &'a [(String, String)],
) -> Option<(&'a str, &'a str)> {
    for (name, class) in bare_locals {
        if has_coercion(text, name) {
            return Some((name.as_str(), class.as_str()));
        }
    }
    None
}

fn has_coercion(text: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let template = format!("${{{name}}}");
    if text.contains(&template) {
        return true;
    }
    let string_call = format!("String({name})");
    if text.contains(&string_call) {
        return true;
    }
    let plus_left = format!("{name} + \"");
    let plus_left_single = format!("{name} + '");
    let plus_right = format!("\" + {name}");
    let plus_right_single = format!("' + {name}");
    text.contains(&plus_left)
        || text.contains(&plus_left_single)
        || text.contains(&plus_right)
        || text.contains(&plus_right_single)
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
