//! `cc.modernize.os_path_join` — Python `os.path.join` over `pathlib.Path`.
//!
//! Mirrors ruff `PTH118` (and the broader `PTH*` family). Detects calls
//! whose canonical callee text matches anything in
//! `crate::helpers::OS_PATH_CALLEES` and points the user at `pathlib`.
//!
//! Severity: `Nit` — both spellings are correct; pathlib is just the
//! modern idiom.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint, OS_PATH_CALLEES,
};

/// Family-26 probe `cc.modernize.os_path_join`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsPathJoinRule;

impl Rule for OsPathJoinRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.os_path_join"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "Python `os.path.*` calls superseded by `pathlib.Path`"
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
    let matched = OS_PATH_CALLEES.iter().find(|c| text.contains(*c))?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !path.as_str().ends_with(".py") {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.os_path_join",
        severity: Severity::Nit,
        confidence: Confidence::new(0.8),
        location,
        headline: format!("`{matched}` superseded by `pathlib.Path`"),
        explanation: format!(
            "`{matched}` is correct but stringly-typed: paths flow through \
             the function as `str`, callers cannot tell platform-correct \
             joins from raw concatenation, and operations like `with_suffix` \
             require manual splitting. `pathlib.Path` exposes the same \
             behaviour with type-safe operators."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace `os.path.join(a, b)` with `Path(a) / b`, \
             `os.path.exists(p)` with `Path(p).exists()`, \
             `os.path.dirname(p)` with `Path(p).parent`."
                .into(),
        ),
        snippet: text,
        weight: 1,
    }))
}
