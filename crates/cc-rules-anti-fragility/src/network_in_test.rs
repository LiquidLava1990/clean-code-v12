//! `cc.fragile.network_in_test` — test reaches an external host.
//!
//! Heuristic: in test files, walk every [`NodeKind::Call`] whose callee
//! matches the same outbound-HTTP table as `cc.taint.ssrf`. If the URL
//! argument does NOT resolve to a localhost / loopback / mock-server
//! literal, fire — the test depends on a host the CI runner cannot
//! guarantee is reachable.
//!
//! Non-test files are silent — production HTTP belongs to other rules
//! (taint, perf).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, call_url_text, callee_text, enclosing_file_path, is_test_file_path,
    location_from_node, looks_like_localhost, AntiFragilityFindingBlueprint, HTTP_CALLEES,
};

/// Family-23 probe `cc.fragile.network_in_test`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NetworkInTestRule;

impl Rule for NetworkInTestRule {
    fn rule_id(&self) -> &'static str {
        "cc.fragile.network_in_test"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Fragile
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "test calls an outbound HTTP API against a non-localhost URL"
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
    let callee = callee_text(ctx.batch, id);
    if !matches_http_callee(&callee) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if !is_test_file_path(&path) {
        return None;
    }
    let url = call_url_text(ctx.batch, id);
    if looks_like_localhost(&url) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    let snippet = format_snippet(&callee, &url);
    Some(build_finding(AntiFragilityFindingBlueprint {
        rule_id: "cc.fragile.network_in_test",
        severity: Severity::Required,
        confidence: Confidence::new(0.8),
        location,
        headline: "test reaches an external host — flake risk".into(),
        explanation: "Tests that hit live external hosts fail every time the \
             upstream API is slow, rate-limited, or down. CI cannot guarantee \
             reachability, and a green run becomes a coin flip."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Stand up a local HTTP fixture (`httptest.NewServer`, `mockito`, \
             `wiremock`, `MockServer`) or stub the client at the unit-test \
             boundary, then point the test at `http://127.0.0.1:<port>` / \
             `http://localhost`."
                .into(),
        ),
        snippet,
        weight: 3,
    }))
}

fn matches_http_callee(text: &str) -> bool {
    HTTP_CALLEES.iter().any(|needle| text.contains(needle))
}

fn format_snippet(callee: &str, url: &str) -> String {
    if url.is_empty() {
        callee.to_owned()
    } else {
        format!("{callee} -> {url}")
    }
}
