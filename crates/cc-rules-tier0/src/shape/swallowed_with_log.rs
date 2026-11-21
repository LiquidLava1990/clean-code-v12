//! Tier-0 forever rule R-SWALLOWED-WITH-LOG.
//!
//! Flag `try` / `except` (Python), `try` / `catch` (TS / Java),
//! `if let Err(_)` (Rust) handlers whose body only logs and never
//! propagates: no `return`, no `raise` / `throw`, no `?` / `return Err(...)`,
//! no re-raise. Promoted from Family 25 to Tier-0 per the OSS delta
//! recommendation — silent error-swallow is the highest-frequency
//! incident-amplifier we see in production reviews.
//!
//! Detection strategy:
//! - Iterate `Try` nodes.
//! - For each handler block (carried in the `catches` property as
//!   `Value::NodeList`, or fall back to scanning child `Block` nodes),
//!   read its source byte range.
//! - If the body contains a logging call (`log.error`, `console.error`,
//!   `eprintln!`, `tracing::error!`, `logger.error`, `slog.Error`, …)
//!   AND no propagation token (`return`, `raise`, `throw`, ` ? `,
//!   `return Err(`, `panic!`), fire.

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind, Value};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_by_id, node_kind, nodes_of_kind, range_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, byte_window, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, Tier0FindingBlueprint,
};

const LOG_NEEDLES: &[&str] = &[
    "log.error",
    "log.warning",
    "log.warn",
    "log.exception",
    "logger.error",
    "logger.warning",
    "logger.warn",
    "logger.exception",
    "console.error",
    "console.warn",
    "eprintln!",
    "tracing::error",
    "tracing::warn",
    "slog.Error",
    "zap.Error",
    "fmt.Println",
];

const PROPAGATION_NEEDLES: &[&str] = &[
    "return ",
    "return;",
    "raise ",
    "raise;",
    "throw ",
    "throw;",
    "panic!",
    "?;",
    "?)",
    "Err(",
    ".context(",
    "re-raise",
];

/// Tier-0 forever rule R-SWALLOWED-WITH-LOG.
#[derive(Debug, Default, Clone, Copy)]
pub struct SwallowedWithLogRule;

impl Rule for SwallowedWithLogRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.swallowed_with_log_no_recovery"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "catch / except handler logs but does not propagate"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Try) {
            if let Some(finding) = check_try(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_try(ctx: &RuleContext<'_>, try_id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, try_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return None;
    }
    if !any_handler_swallows(ctx.batch, try_id, bytes) {
        return None;
    }
    let location = location_from_node(ctx.batch, try_id, path);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.swallowed_with_log_no_recovery",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: "exception handler logs but does not propagate".into(),
        explanation: "The handler body calls a logging function but does not return, re-raise, \
             or propagate the error. Silent swallow + log is the highest-frequency \
             incident-amplifier pattern in production: the call site believes the \
             operation succeeded, then fails downstream with no breadcrumb."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Either re-raise the original exception (`raise`, `throw e`, `?`, \
             `return Err(...)`) after logging, or convert the failure into an \
             explicit recovery action with a comment explaining the chosen recovery."
                .into(),
        ),
        snippet: String::new(),
        weight: 2,
    }))
}

fn any_handler_swallows(batch: &CpgWriteBatch, try_id: NodeId, bytes: &[u8]) -> bool {
    let handlers = collect_handlers(batch, try_id);
    handlers
        .into_iter()
        .any(|h| handler_body_swallows(batch, h, bytes))
}

fn collect_handlers(batch: &CpgWriteBatch, try_id: NodeId) -> Vec<NodeId> {
    if let Some(node) = node_by_id(batch, try_id) {
        if let Some(Value::NodeList(ids)) = node.prop("catches") {
            return ids.clone();
        }
    }
    ast_children(batch, try_id)
        .filter(|c| node_kind(batch, *c) == Some(NodeKind::Block))
        .collect()
}

fn handler_body_swallows(batch: &CpgWriteBatch, handler_id: NodeId, bytes: &[u8]) -> bool {
    let Some(range) = range_prop(batch, handler_id, "range") else {
        return false;
    };
    let body = byte_window(bytes, range.start.offset, range.end.offset);
    let text = std::str::from_utf8(body).unwrap_or("");
    if !text_contains_any(text, LOG_NEEDLES) {
        return false;
    }
    if text_contains_any(text, PROPAGATION_NEEDLES) {
        return false;
    }
    true
}

fn text_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}
