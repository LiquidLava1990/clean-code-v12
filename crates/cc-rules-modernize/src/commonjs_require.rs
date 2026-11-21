//! `cc.modernize.commonjs_require` — JavaScript `require(...)` calls
//! superseded by ESM `import`.
//!
//! Mirrors unicorn `prefer-module` and ts-eslint `no-require-imports`.
//! Detection: any [`NodeKind::Call`] whose canonical callee text is
//! exactly `require` (or starts with `require(`) inside a JS/TS source
//! file outside `node_modules`.
//!
//! Severity: `Required` — Node.js 22 deprecated `require()` for ESM
//! interop in favour of dynamic `import()`.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.commonjs_require`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommonjsRequireRule;

const JS_EXTS: &[&str] = &[".js", ".jsx", ".mjs", ".ts", ".tsx"];

impl Rule for CommonjsRequireRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.commonjs_require"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "JavaScript `require(...)` superseded by ESM `import`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let text = callee_text(ctx.batch, id);
    if !is_require_callee(&text) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let path_str = path.as_str();
    if path_str.contains("node_modules") {
        return None;
    }
    if !JS_EXTS.iter().any(|ext| path_str.ends_with(ext)) {
        return None;
    }
    if path_str.ends_with(".cjs") {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.commonjs_require",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "`require(...)` superseded by ESM `import`".into(),
        explanation: "CommonJS `require` runs synchronously, blocks the \
             event loop on cold paths, and breaks tree-shaking. ESM \
             `import` is the standard module system across Node.js, \
             Deno, Bun, and the browser, with first-class top-level \
             `await` and lazy `import()` for dynamic loads."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `const x = require('m')` with `import x from 'm'` (or \
             `import { … } from 'm'` for named exports). For dynamic \
             loading use `await import('m')`."
                .into(),
        ),
        snippet: text,
        weight: 1,
    }))
}

fn is_require_callee(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let needles = ["require", "require("];
    needles.iter().any(|n| text == *n)
        || text.starts_with("require ")
        || text.starts_with("require(")
        || text.contains(" require ")
        || text.contains(" require(")
}
