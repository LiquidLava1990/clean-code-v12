//! `cc.modernize.logging_fstring` — `logging.info(f"...")` /
//! `logger.error(f"...")`. f-strings are formatted eagerly at the call
//! site, even when the configured log level filters the message out —
//! wasting CPU and breaking lazy `%`-style formatting that the logging
//! module is designed for.
//!
//! Mirrors ruff `G004` (logging-f-string).
//!
//! Phase-9 detector: scan every Python file once for `logger.<level>(`
//! / `logging.<level>(` / `LOG.<level>(` invocations whose first
//! positional argument is an f-string literal (`f"…"` or `f'…'`).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.logging_fstring`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoggingFstringRule;

/// Standard logging level methods.
const LOG_METHODS: &[&str] = &[
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "exception",
    "critical",
    "fatal",
    "log",
];

/// Logger-bearing receivers commonly used in Python projects.
const LOG_RECEIVERS: &[&str] = &["logger", "logging", "log", "LOG", "_logger", "_log"];

impl Rule for LoggingFstringRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.logging_fstring"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "logger call with f-string formats eagerly even when filtered"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
                continue;
            }
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (line_idx, line) in text.lines().enumerate() {
        if let Some(method) = find_logger_fstring(line) {
            out.push(emit(path.clone(), line_idx + 1, line, method));
        }
    }
}

/// Search for `<receiver>.<method>(f"...` on this line. Returns the
/// matched method on hit.
fn find_logger_fstring(line: &str) -> Option<&'static str> {
    for receiver in LOG_RECEIVERS {
        let prefix = format!("{receiver}.");
        if let Some(method) = scan_receiver(line, &prefix) {
            return Some(method);
        }
    }
    None
}

fn scan_receiver(line: &str, prefix: &str) -> Option<&'static str> {
    let mut start = 0usize;
    while let Some(found) = line[start..].find(prefix) {
        let abs = start + found;
        if has_token_prefix(line, abs) {
            start = abs + prefix.len();
            continue;
        }
        if let Some(method) = match_logger_call(&line[abs + prefix.len()..]) {
            return Some(method);
        }
        start = abs + prefix.len();
    }
    None
}

fn has_token_prefix(line: &str, abs: usize) -> bool {
    if abs == 0 {
        return false;
    }
    let prev = line.as_bytes()[abs - 1];
    prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'.'
}

/// `after` starts right after `<receiver>.` — match `<method>(f"...`.
fn match_logger_call(after: &str) -> Option<&'static str> {
    for method in LOG_METHODS {
        let needle = format!("{method}(");
        if let Some(rest) = after.strip_prefix(&needle) {
            let trimmed = rest.trim_start();
            if trimmed.starts_with("f\"")
                || trimmed.starts_with("f'")
                || trimmed.starts_with("rf\"")
                || trimmed.starts_with("rf'")
                || trimmed.starts_with("fr\"")
                || trimmed.starts_with("fr'")
            {
                return Some(method);
            }
        }
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, method: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.logging_fstring",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`logger.{method}(f\"...\")` formats eagerly even when filtered"),
        explanation: format!(
            "f-strings are formatted at the call site, before the logging \
             module gets a chance to check the configured level. When \
             `{method}` is filtered out, the work was wasted — and \
             worse, exceptions raised during interpolation now happen \
             on the caller side instead of being swallowed by the \
             logging handler. The classic `%`-style form keeps \
             formatting lazy: it only runs when a handler actually \
             emits the record."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Use the `%` placeholder form and pass values as args: \
             `logger.{method}(\"user=%s id=%d\", name, uid)`. The \
             logging module performs the substitution only if a \
             handler will emit. For structured logging, pass \
             `extra={{...}}` instead of inlining values into the \
             message."
        )),
        snippet,
        weight: 2,
    })
}
