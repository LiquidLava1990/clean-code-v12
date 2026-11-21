//! `cc.complete.public_fn_no_test` — public, exported function with no
//! visible test of its name.
//!
//! Heuristic — Phase-10 grade, single-file scope:
//! 1. Enumerate every `Function` / `Method` whose enclosing file is NOT
//!    a test file.
//! 2. Skip non-public ones (sub-folder helpers / `_underscore` Python
//!    methods / non-`pub` Rust fns).
//! 3. Look across the *same batch* for any function whose name contains
//!    the public function's name AND lives in a path the
//!    `crate::helpers::is_test_file_path`-equivalent matches. If
//!    none, emit a finding.
//!
//! Cross-file aggregation is deferred to a Phase-12 follow-up that
//! consumes the persistent CPG store rather than the per-batch view.
//! This probe stays best-effort in the meantime — confidence 0.7
//! reflects that.
//!
//! OSS source: `cargo mutants` no-test heuristic, `nyc` (Istanbul)
//! `--check-coverage`-driven gates, JaCoCo `INSTRUCTION` thresholds,
//! pytest-cov `--fail-under`, Sonar `python:S2187` (test-file present).

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_public_fn, is_top_level_fn, location_from_node,
    CompletenessFindingBlueprint,
};

/// Probe `cc.complete.public_fn_no_test`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PublicFnNoTestRule;

impl Rule for PublicFnNoTestRule {
    fn rule_id(&self) -> &'static str {
        "cc.complete.public_fn_no_test"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "public function lacks a same-batch test naming it (heuristic, single-file scope)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let test_names = collect_test_function_names(ctx);
        let mut out = Vec::new();
        for fn_node in nodes_of_kind(ctx.batch, NodeKind::Function) {
            if let Some(f) = check_fn(ctx, fn_node.id, &test_names) {
                out.push(f);
            }
        }
        out
    }
}

/// Collect every function name in the batch whose enclosing file looks
/// like a test file. Returned set is searched as a haystack; matching
/// is `contains`-based so `test_my_helper` matches public fn
/// `my_helper`.
fn collect_test_function_names(ctx: &RuleContext<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for fn_node in nodes_of_kind(ctx.batch, NodeKind::Function) {
        let Some(name) = string_prop(ctx.batch, fn_node.id, "name") else {
            continue;
        };
        let Some(path) = enclosing_file_path(ctx.batch, fn_node.id) else {
            continue;
        };
        if path_looks_like_test(&path) {
            out.push(name.to_owned());
        }
    }
    out
}

fn path_looks_like_test(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    if s.contains("/tests/") || s.contains("/test/") || s.contains("/__tests__/") {
        return true;
    }
    path.file_stem().is_some_and(|stem| {
        let lower = stem.to_ascii_lowercase();
        lower.starts_with("test_")
            || lower.ends_with("_test")
            || lower.ends_with(".test")
            || lower.ends_with(".spec")
    })
}

fn check_fn(ctx: &RuleContext<'_>, id: NodeId, test_names: &[String]) -> Option<Finding> {
    if !is_top_level_fn(ctx.batch, id) {
        return None;
    }
    if !is_public_fn(ctx.batch, id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if path_looks_like_test(&path) {
        return None;
    }
    if is_underscore_python_method(ctx.batch, id) {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name")?;
    if name.is_empty() {
        return None;
    }
    if test_names.iter().any(|t| t.contains(name)) {
        return None;
    }
    Some(emit(ctx, id, &path, name))
}

fn is_underscore_python_method(batch: &cc_cpg::CpgWriteBatch, id: NodeId) -> bool {
    string_prop(batch, id, "name").is_some_and(|n| n.starts_with('_'))
}

fn emit(ctx: &RuleContext<'_>, id: NodeId, path: &Utf8PathBuf, name: &str) -> Finding {
    let location = location_from_node(ctx.batch, id, path.clone());
    build_finding(CompletenessFindingBlueprint {
        rule_id: "cc.complete.public_fn_no_test",
        category: Category::Obs,
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("public fn `{name}` has no visible test (heuristic, same-batch scope)"),
        explanation: "No test function name in this batch contains \
             the public function's name. The heuristic only scans the \
             current parse-batch — cross-file aggregation lands when \
             the persistent CPG store is wired into rule contexts. Until \
             then, treat this probe as a best-effort coverage hint: a \
             genuine miss should be promoted to a real test, a false \
             positive can be silenced by naming the test after the \
             function (`test_<name>`)."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add a test whose name contains this function's name. \
             `test_<name>_<scenario>` is the canonical form across \
             pytest, Rust `#[test]`, and JS test runners."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 1,
    })
}
