//! `cc.test.disabled_test` — test marked skip / xit / `#[ignore]` /
//! `@pytest.mark.skip` without a reason text in 80 chars after the marker.
//!
//! Heuristic: walk every [`NodeKind::Decorator`] / attribute under a
//! Function or Method and look for the canonical disable markers. A
//! decorator whose text contains `(reason=...)` / `("...")` / `= "..."`
//! within 80 chars of the marker is considered documented and
//! suppressed; everything else fires.

use cc_cpg::{EdgeKind, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{incoming_edges_of_kind, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    TestDesignFindingBlueprint,
};

/// Family-28 probe `cc.test.disabled_test`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledTestRule;

/// Substring needles that mark a test as disabled / skipped.
const DISABLE_MARKERS: &[&str] = &[
    "ignore", // Rust #[ignore]
    "skip",   // pytest.mark.skip, jest test.skip, jest describe.skip
    "skipif", // pytest.mark.skipif
    "xit",    // jest xit / xdescribe
    "xdescribe",
    "xtest",
    "skip(",
    "todo(", // jest test.todo
    "fdescribe",
    "fit(",
    "skipped",
    "skipUnless",
    "expectedFailure",
];

impl Rule for DisabledTestRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.disabled_test"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "test disabled without reason text — silent regression risk"
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
    let (decorator_id, marker_text) = find_disable_marker(ctx, fn_id)?;
    if marker_has_reason(&marker_text) {
        return None;
    }
    let name = string_prop(ctx.batch, fn_id, "name").unwrap_or("");
    let location = location_from_node(ctx.batch, decorator_id, path);
    Some(build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.disabled_test",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("test `{name}` disabled without reason"),
        explanation: format!(
            "`{name}` carries a skip / ignore / xit marker but no reason \
             text in the next 80 chars. A disabled test that nobody \
             documents stays disabled forever — this is how regressions \
             ship. Either re-enable the test or document why it must \
             stay off."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add a reason: `#[ignore = \"flaky on Windows — INV-NN\"]` / \
             `@pytest.mark.skip(reason=\"...\")` / `it.skip('...', () => {…})`. \
             If the test is obsolete, delete it."
                .into(),
        ),
        snippet: marker_text,
        weight: 3,
    }))
}

fn find_disable_marker(ctx: &RuleContext<'_>, fn_id: NodeId) -> Option<(NodeId, String)> {
    for edge in incoming_edges_of_kind(ctx.batch, fn_id, EdgeKind::AST_PARENT) {
        if node_kind(ctx.batch, edge.from) != Some(NodeKind::Decorator) {
            continue;
        }
        let text = decorator_full_text(ctx, edge.from);
        let lower = text.to_ascii_lowercase();
        if DISABLE_MARKERS.iter().any(|m| lower.contains(m)) {
            return Some((edge.from, text));
        }
    }
    None
}

fn decorator_full_text(ctx: &RuleContext<'_>, decorator_id: NodeId) -> String {
    let mut buf = String::new();
    for key in ["name", "expression", "qualified", "arguments"] {
        if let Some(value) = string_prop(ctx.batch, decorator_id, key) {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(value);
        }
    }
    buf
}

/// True iff the decorator text contains a reason string within the
/// first 80 chars after the marker. We accept any of: a parenthesised
/// non-empty string literal, an `= "..."` assignment, a `reason=` /
/// `because=` / `note=` keyword arg.
fn marker_has_reason(text: &str) -> bool {
    let window = &text[..text.len().min(80)];
    let lower = window.to_ascii_lowercase();
    if lower.contains("reason") || lower.contains("because") || lower.contains("note=") {
        return true;
    }
    contains_quoted_payload(window)
}

fn contains_quoted_payload(window: &str) -> bool {
    let bytes = window.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if !is_quote_byte(c) {
            i += 1;
            continue;
        }
        let Some(end) = bytes[i + 1..].iter().position(|b| *b == c) else {
            i += 1;
            continue;
        };
        if end > 0 {
            return true;
        }
        i += end + 2;
    }
    false
}

const fn is_quote_byte(c: u8) -> bool {
    c == b'"' || c == b'\''
}
