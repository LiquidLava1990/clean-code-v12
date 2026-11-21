//! `cc.test.assertion_free` — a test runs but asserts nothing.
//!
//! Heuristic: enumerate every [`NodeKind::Function`] / [`NodeKind::Method`]
//! node whose enclosing file is a test file (per
//! `crate::helpers::is_test_file_path`) AND whose name / decorator
//! signature looks like a test. For each such function, count
//! [`NodeKind::Call`] descendants whose callee text contains any
//! `crate::helpers::ASSERT_CALLEES` needle. Zero hits ⇒ finding.
//!
//! Function descendants are enumerated transitively via the
//! `AST_PARENT` chain: every Call whose ancestor chain includes the
//! function is in scope. Bounded to 256 hops per descendant to bound
//! pathological depth.
//!
//! This is the only Family-8 probe that runs against real source today;
//! the remaining four heuristic stubs need data the kernel does not
//! yet surface.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_by_id, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, function_has_test_attr, is_test_file_path,
    location_from_node, looks_like_test_name, TestsFindingBlueprint, ASSERT_CALLEES,
};

/// Family-8 probe R-TEST-ASSERTION-FREE.
#[derive(Debug, Default, Clone, Copy)]
pub struct AssertionFreeRule;

impl Rule for AssertionFreeRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.assertion_free"
    }
    fn category(&self) -> Category {
        Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "test function runs but asserts nothing"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_function(ctx: &RuleContext<'_>, fn_id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, fn_id)?;
    if !is_test_file_path(&path) {
        return None;
    }
    let name = string_prop(ctx.batch, fn_id, "name").unwrap_or("");
    if !looks_like_test_name(name) && !function_has_test_attr(ctx.batch, fn_id) {
        return None;
    }
    if function_has_assertion(ctx, fn_id) {
        return None;
    }
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(TestsFindingBlueprint {
        rule_id: "cc.test.assertion_free",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("test `{name}` asserts nothing"),
        explanation: format!(
            "Test `{name}` exercises code but does not call any assertion \
             API (assert!, assert_eq!, expect, assertEqual, t.Errorf, …). A \
             test with no assertions cannot fail; it provides regression \
             coverage in name only."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add at least one assertion that pins the behavior under test \
             (return value, observable side-effect, or raised error). If \
             the test is intentionally a smoke / setup harness, rename it \
             so it is not picked up by the test runner."
                .into(),
        ),
        snippet: name.to_owned(),
        weight: 3,
    }))
}

/// True iff the function subtree contains at least one assertion call.
fn function_has_assertion(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    nodes_of_kind(ctx.batch, NodeKind::Call)
        .any(|call| call_in_function(ctx, call.id, fn_id) && call_is_assertion(ctx, call.id))
}

/// True iff every link in `call`'s ancestor chain eventually reaches
/// `fn_id` within 256 hops.
fn call_in_function(ctx: &RuleContext<'_>, call_id: NodeId, fn_id: NodeId) -> bool {
    let mut cursor = call_id;
    for _ in 0..256_u16 {
        let Some(parent) = ast_parent(ctx.batch, cursor) else {
            return false;
        };
        if parent == fn_id {
            return true;
        }
        cursor = parent;
    }
    false
}

/// True iff the call site looks like an assertion.
///
/// Frontends store callee identity in different slots; concatenate the
/// usual suspects (`callee_ref`, `name`, `signature`, `qualified`,
/// `callee`) and substring-match against [`ASSERT_CALLEES`].
fn call_is_assertion(ctx: &RuleContext<'_>, call_id: NodeId) -> bool {
    let Some(node) = node_by_id(ctx.batch, call_id) else {
        return false;
    };
    if node.kind != NodeKind::Call {
        return false;
    }
    let mut text = String::new();
    for key in [
        "callee_ref",
        "name",
        "signature",
        "qualified",
        "callee",
        "method",
    ] {
        if let Some(value) = string_prop(ctx.batch, call_id, key) {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(value);
        }
    }
    ASSERT_CALLEES.iter().any(|needle| text.contains(needle))
}
