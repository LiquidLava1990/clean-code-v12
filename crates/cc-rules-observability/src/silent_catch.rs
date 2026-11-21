//! `cc.obs.silent_catch` — exception logged then swallowed.
//!
//! Heuristic: every [`NodeKind::Try`] node has its handler-block source
//! text inspected. If that text contains a log-error call (e.g.
//! `log.error`, `tracing::error`, `console.error`, `slog::error`) AND
//! does NOT contain any of the canonical re-raise / propagation markers
//! ([`crate::helpers::RERAISE_MARKERS`]) downstream of the log call, the
//! handler is "silently catching" — visible only as a stranded log line.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ObsFindingBlueprint, LOG_CALLEES, RERAISE_MARKERS,
};
use cc_finding::Category;

/// Family-11 probe R-OBS-SILENT-CATCH.
#[derive(Debug, Default, Clone, Copy)]
pub struct SilentCatchRule;

const ERROR_LEVEL_LOG_NEEDLES: &[&str] = &[
    "log.error",
    "logger.error",
    "logging.error",
    "tracing::error",
    "console.error",
    "slog::error",
    "slog.Error",
    "log.Error",
];

impl Rule for SilentCatchRule {
    fn rule_id(&self) -> &'static str {
        "cc.obs.silent_catch"
    }
    fn category(&self) -> Category {
        Category::Obs
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.75)
    }
    fn description(&self) -> &'static str {
        "exception caught, logged at error, then swallowed without re-raise"
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
    let body = handler_body_text(ctx, try_id, &path)?;
    if !contains_error_log(&body) {
        return None;
    }
    if contains_reraise(&body) {
        return None;
    }
    if !mentions_log_callee(&body) {
        return None;
    }
    let location = location_from_node(ctx.batch, try_id, path);
    Some(emit(location, &body))
}

fn handler_body_text(ctx: &RuleContext<'_>, try_id: NodeId, path: &Utf8PathBuf) -> Option<String> {
    let range = range_prop(ctx.batch, try_id, "range")?;
    let bytes = ctx.source.get(path);
    let start = range.start.offset as usize;
    let end = (range.end.offset as usize).min(bytes.len());
    if start >= end {
        return None;
    }
    let slice = bytes.get(start..end)?;
    let text = String::from_utf8_lossy(slice).into_owned();
    Some(text)
}

fn contains_error_log(body: &str) -> bool {
    ERROR_LEVEL_LOG_NEEDLES.iter().any(|n| body.contains(n))
}

fn mentions_log_callee(body: &str) -> bool {
    LOG_CALLEES.iter().any(|n| body.contains(n))
}

fn contains_reraise(body: &str) -> bool {
    RERAISE_MARKERS.iter().any(|n| body.contains(n))
}

fn emit(location: cc_finding::Location, body: &str) -> Finding {
    let snippet: String = body.chars().take(180).collect();
    build_finding(ObsFindingBlueprint {
        rule_id: "cc.obs.silent_catch",
        severity: Severity::Required,
        confidence: Confidence::new(0.75),
        location,
        headline: "exception caught, logged at `error`, then swallowed".into(),
        explanation: "The handler logs the exception at `error` level and \
             then returns normally — callers never learn the operation \
             failed. A logged-and-dropped error reduces a hard failure to \
             a stranded log line; the parent flow keeps running on stale \
             or missing data."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Re-raise (`raise` / `throw`), return a typed error \
             (`Err(...)` / `return err`), or `panic!` after logging. If \
             the failure truly is recoverable, log at `warn` and document \
             the chosen fallback in code."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
