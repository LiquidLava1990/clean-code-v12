//! `cc.type.no_confusing_void_expression` — `void` operator used as if
//! it were a value-producing expression.
//!
//! Syntactic shadow of TypeScript ESLint's
//! `no-confusing-void-expression`. The `void` operator evaluates its
//! argument and returns `undefined`; readers commonly mistake it for
//! the `void` type or a discard operator. Common confusions:
//!
//! - `() => void doSomething()` — arrow returning the result of `void`,
//!   discarding the real return value silently.
//! - `return void x` — function returns `undefined` after evaluating
//!   `x`, but the spelling implies "x is void".
//! - `const y = void something()` — `y` is forced to `undefined`,
//!   throwing away the actual return value.
//!
//! Detection scans the same text properties used by other Family-22
//! probes and looks for the patterns:
//! - `=> void <name>(`
//! - `return void <name>(`
//! - `= void <name>(`
//! - `(void <name>(`
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

/// Family-22 probe R-TYPE-NO-CONFUSING-VOID-EXPRESSION.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoConfusingVoidExpressionRule;

const TEXT_PROPS: &[&str] = &[
    "expression",
    "text",
    "value",
    "arguments",
    "condition",
    "return_expressions",
];

const NEEDLES: &[(&str, &str)] = &[
    ("=> void ", "arrow body uses `void` operator"),
    (
        "return void ",
        "`return void <expr>` returns undefined silently",
    ),
    ("= void ", "assignment of `void <expr>` forces undefined"),
    ("(void ", "`void` operator inside expression position"),
];

impl Rule for NoConfusingVoidExpressionRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_confusing_void_expression"
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
        "`void` operator used in a value-producing position"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [
            NodeKind::Function,
            NodeKind::Method,
            NodeKind::Variable,
            NodeKind::Write,
            NodeKind::Call,
            NodeKind::Async,
        ] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_node(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_node(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
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
    let text = first_text(ctx, id)?;
    let (needle, label) = match_needle(text)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_confusing_void_expression",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("confusing `void` operator usage ({label})"),
        explanation: format!(
            "`{needle}` evaluates the inner expression and then yields \
             `undefined`. Readers commonly mistake the postfix `void` for \
             the `void` type or a discard intent. The actual semantics are \
             usually surprising: the inner expression's return value is \
             thrown away, and the surrounding context is forced to \
             `undefined`."
        ),
        remediation: Remediation::SuggestedRewrite(
            "If the goal is fire-and-forget, prefer an explicit statement \
             form: `someAsyncFn();` (then await or chain) — not `void \
             someAsyncFn()`. If the goal is to mark a fire-and-forget \
             intentionally, add a comment `// fire-and-forget: <reason>`. \
             For arrows, use a block body: `() => { doSomething(); }`."
                .into(),
        ),
        snippet: text.to_owned(),
        weight: 1,
    }))
}

fn first_text<'b>(ctx: &RuleContext<'b>, id: NodeId) -> Option<&'b str> {
    for key in TEXT_PROPS {
        if let Some(text) = string_prop(ctx.batch, id, key) {
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn match_needle(text: &str) -> Option<(&'static str, &'static str)> {
    for (needle, label) in NEEDLES {
        if text.contains(needle) {
            return Some((*needle, *label));
        }
    }
    None
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
