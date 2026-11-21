//! `cc.perf.regex_compile_in_loop` — regex compilation inside a loop body.
//!
//! Algorithm: every [`NodeKind::Call`] whose callee text matches one of
//! the four canonical regex compile entry points (`re.compile`,
//! `Regex::new`, `regexp.MustCompile`, `new RegExp`) gets its
//! `AST_PARENT` chain walked. If a [`NodeKind::Loop`] sits between the
//! call and the enclosing [`NodeKind::Function`], the call recompiles
//! the pattern once per iteration — hoist it out of the loop.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_inside_loop, location_from_node,
    PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-REGEX-COMPILE-IN-LOOP.
#[derive(Debug, Default, Clone, Copy)]
pub struct RegexCompileInLoopRule;

/// Canonical regex-compile entry points across the four supported
/// languages. Each entry is matched as a substring on the callee text.
const REGEX_COMPILE: &[&str] = &[
    "re.compile",
    "Regex::new",
    "regexp.MustCompile",
    "new RegExp",
];

impl Rule for RegexCompileInLoopRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.regex_compile_in_loop"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.92)
    }
    fn description(&self) -> &'static str {
        "regex compiled inside a loop body — hoist out of the loop"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            let text = callee_text(ctx.batch, node.id);
            let Some(hit) = REGEX_COMPILE.iter().find(|needle| text.contains(*needle)) else {
                continue;
            };
            if !is_inside_loop(ctx.batch, node.id) {
                continue;
            }
            if let Some(finding) = emit(ctx, node.id, hit) {
                out.push(finding);
            }
        }
        out
    }
}

fn emit(ctx: &RuleContext<'_>, call: NodeId, compile_call: &str) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call)?;
    let location = location_from_node(ctx.batch, call, path);
    Some(build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.regex_compile_in_loop",
        severity: Severity::Required,
        confidence: Confidence::new(0.92),
        location,
        headline: format!("`{compile_call}` recompiles every loop iteration"),
        explanation: format!(
            "Compiling a regex is O(pattern-length); doing it inside the loop \
             multiplies the cost by the iteration count. Hoist the \
             `{compile_call}` call to module scope (or the enclosing function) \
             and reuse the compiled pattern in the hot path."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Move the compile call to module-level / function-prologue scope and \
             reference the compiled pattern from inside the loop."
                .into(),
        ),
        snippet: String::new(),
        weight: 2,
    }))
}
