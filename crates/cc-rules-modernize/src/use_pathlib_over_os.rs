//! `cc.modernize.use_pathlib_over_os` — Python `os.path.exists`,
//! `os.path.isfile`, `os.path.isdir`, `os.path.basename`,
//! `os.path.dirname`, `os.path.splitext`, `os.path.getsize`,
//! `os.path.abspath` superseded by the equivalent `pathlib.Path`
//! method.
//!
//! Mirrors the ruff `PTH100`–`PTH150` family (`PTH110` exists,
//! `PTH112` isfile, `PTH113` isdir, `PTH117` not-a-link, `PTH119`
//! basename, `PTH120` dirname, `PTH122` splitext, `PTH202` getsize).
//! `os.path.join` is intentionally excluded — the Phase-6 probe
//! `cc.modernize.os_path_join` owns that callee.
//!
//! Severity: `Nit` — both spellings are correct; `pathlib` is the
//! modern idiom.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint, OS_PATH_PATHLIB_CALLEES,
};

/// Family-26 probe `cc.modernize.use_pathlib_over_os`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UsePathlibOverOsRule;

impl Rule for UsePathlibOverOsRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.use_pathlib_over_os"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Python `os.path.{exists,isfile,…}` superseded by `pathlib.Path`"
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
    if text.is_empty() {
        return None;
    }
    let (legacy, replacement) = matched_callee(&text)?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !path.as_str().ends_with(".py") {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.use_pathlib_over_os",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{legacy}` superseded by `{replacement}`"),
        explanation: format!(
            "`{legacy}` returns a stringly-typed result that callers must \
             feed back through more `os.path.*` calls or raw concatenation. \
             `pathlib.Path` exposes the same behaviour as `{replacement}` \
             with object identity, type-safe `/` joins, and properties like \
             `.parent` / `.stem` that compose without re-parsing the string."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace `{legacy}(p)` with `{replacement}`. The whole \
             `os.path` family swaps cleanly to `pathlib.Path`; doing the \
             rewrite once at module scope keeps the rest of the file \
             type-consistent."
        )),
        snippet: text,
        weight: 1,
    }))
}

fn matched_callee(text: &str) -> Option<(&'static str, &'static str)> {
    OS_PATH_PATHLIB_CALLEES
        .iter()
        .find(|(legacy, _)| text.contains(legacy))
        .map(|(legacy, replacement)| (*legacy, *replacement))
}
