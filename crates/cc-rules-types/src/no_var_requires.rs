//! `cc.type.no_var_requires` — `const x = require('mod')` (CommonJS)
//! inside a TypeScript file.
//!
//! Syntactic shadow of TypeScript ESLint's `no-var-requires`. Distinct
//! from the broader `cc.modernize.commonjs_require` (which fires on JS
//! and TS): this probe only fires on TypeScript files where the project
//! has committed to ESM. In a `.ts` file, `require()` defeats type
//! discovery, blocks tree-shaking, and bypasses the module's declared
//! type surface.
//!
//! Detection: every [`NodeKind::Variable`] / [`NodeKind::Write`] whose
//! initializer or expression text contains `require(` and whose
//! enclosing file is `.ts` / `.tsx`.
//!
//! Exclusions:
//! - `.cjs` / `.cts` files (intentional CommonJS).
//! - Test files (test runners often resolve modules via require).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_language, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-TYPE-NO-VAR-REQUIRES.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoVarRequiresRule;

const TEXT_PROPS: &[&str] = &["expression", "initializer", "text", "value"];

impl Rule for NoVarRequiresRule {
    fn rule_id(&self) -> &'static str {
        "cc.type.no_var_requires"
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
        "`const x = require(...)` defeats ESM in a TypeScript file"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Variable, NodeKind::Write] {
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
    if !is_typescript(&language) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let path_str = path.as_str();
    if !is_strict_ts_extension(path_str) {
        return None;
    }
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let text = first_text(ctx, id)?;
    if !mentions_require(text) {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name").unwrap_or("<binding>");
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.type.no_var_requires",
        category: Category::Type,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "TypeScript binding `{name}` uses `require(...)` instead of ESM `import`",
        ),
        explanation: format!(
            "`{name}` is initialised with `require(...)` inside a `.ts` / \
             `.tsx` file. CommonJS `require` defeats TypeScript's type \
             discovery (the binding loses its declared type surface), \
             blocks tree-shaking, and forces synchronous module \
             resolution. The file is committed to ESM by virtue of being \
             `.ts` — use `import`."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace with ESM: `import {name} from 'mod'` (default export) \
             or `import {{ {name} }} from 'mod'` (named export). For \
             dynamic loads, use `const {name} = await import('mod')`."
        )),
        snippet: text.to_owned(),
        weight: 2,
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

fn mentions_require(text: &str) -> bool {
    text.contains("require(") || text.contains("require (")
}

fn is_typescript(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "ts" | "typescript")
}

fn is_strict_ts_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".cts") || lower.ends_with(".cjs") {
        return false;
    }
    lower.ends_with(".ts") || lower.ends_with(".tsx") || lower.ends_with(".mts")
}
