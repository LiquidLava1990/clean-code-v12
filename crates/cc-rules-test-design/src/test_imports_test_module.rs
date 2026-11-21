//! `cc.test.test_imports_test_module` — test file imports another test file.
//!
//! Heuristic: enumerate every [`NodeKind::Import`] in a test file. If
//! the import's target path / module — read from `module_path` /
//! `target_module` / `path` / `source` / `name` — itself looks like a
//! test file, fire. Cross-test coupling is brittle: refactoring or
//! renaming one test breaks unrelated tests.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    TestDesignFindingBlueprint,
};

/// Family-28 probe `cc.test.test_imports_test_module`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TestImportsTestModuleRule;

impl Rule for TestImportsTestModuleRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.test_imports_test_module"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "test file imports another test module — cross-test coupling"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Import) {
            if let Some(finding) = check_import(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_import(ctx: &RuleContext<'_>, import_id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, import_id)?;
    if !is_test_file_path(&path) {
        return None;
    }
    let target = read_import_target(ctx, import_id)?;
    let target_path = Utf8PathBuf::from(target.replace('.', "/"));
    if !is_test_file_path(&target_path) {
        return None;
    }
    let location = location_from_node(ctx.batch, import_id, path);
    Some(build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.test_imports_test_module",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("test imports test module `{target}`"),
        explanation: format!(
            "Test files should depend only on production code (the system \
             under test) and shared fixtures. Importing `{target}` (itself \
             a test module) couples one test to another — refactoring \
             one breaks unrelated tests, and parallel runners may see \
             order-dependent failures."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Extract the shared helper / fixture into a non-test module \
             (e.g. `tests/common/mod.rs`, `tests/helpers/`, a `conftest.py`, \
             or a regular library module) and import that instead."
                .into(),
        ),
        snippet: target,
        weight: 2,
    }))
}

fn read_import_target(ctx: &RuleContext<'_>, import_id: NodeId) -> Option<String> {
    for key in ["module_path", "target_module", "path", "source", "name"] {
        if let Some(value) = string_prop(ctx.batch, import_id, key) {
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}
