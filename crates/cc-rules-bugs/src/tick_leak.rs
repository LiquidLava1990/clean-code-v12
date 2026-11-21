//! `cc.bug.tick_leak` — `time.Tick(...)` called outside `main`.
//!
//! `time.Tick` returns a channel backed by a `*time.Ticker` whose `Stop`
//! method is unreachable (the wrapping ticker is never returned to the
//! caller). Every call therefore leaks a ticker and a goroutine that
//! cannot be reclaimed until the program exits. Inside `main` that is
//! benign — the program is about to exit anyway — but in any library
//! function, long-lived service, or test helper it is a goroutine leak.
//!
//! OSS source: staticcheck SA1015 (`time.Tick leaks the underlying
//! ticker`).
//!
//! Phase-8 source-byte heuristic (Go only): scan every `.go` file for
//! lines containing `time.Tick(` and skip lines whose enclosing function
//! is `func main(`. The "enclosing function" is the most recent `func`
//! header above the line within the file.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-TICK-LEAK.
#[derive(Debug, Default, Clone, Copy)]
pub struct TickLeakRule;

impl Rule for TickLeakRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.tick_leak"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "time.Tick called outside main leaks the underlying ticker"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("go") {
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
    let mut current_fn: &str = "";
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if let Some(func_name) = parse_func_header(trimmed) {
            current_fn = func_name;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        if !trimmed.contains("time.Tick(") {
            continue;
        }
        if current_fn == "main" {
            continue;
        }
        out.push(emit(path.clone(), line_idx + 1, line, current_fn));
    }
}

/// Extract the function name from a Go `func` header line. Returns
/// `None` when the line is not a function declaration.
fn parse_func_header(trimmed: &str) -> Option<&str> {
    let after_func = trimmed.strip_prefix("func ")?;
    let after_receiver = strip_optional_receiver(after_func);
    let name_end = after_receiver
        .find(|c: char| c == '(' || c == '[' || c.is_whitespace())
        .unwrap_or(after_receiver.len());
    let name = &after_receiver[..name_end];
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Strip a `(receiver Type)` block, if present, from the start of `s`.
fn strip_optional_receiver(s: &str) -> &str {
    if !s.starts_with('(') {
        return s;
    }
    match s.find(')') {
        Some(close) => s[close + 1..].trim_start(),
        None => s,
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, enclosing_fn: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: Some(enclosing_fn.to_owned()),
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.tick_leak",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "`time.Tick(...)` in `{}` leaks the underlying ticker",
            if enclosing_fn.is_empty() {
                "<top-level>"
            } else {
                enclosing_fn
            }
        ),
        explanation: "`time.Tick` returns a channel without exposing the underlying \
             `*time.Ticker`, so its `Stop` method is unreachable. Every \
             call leaks a ticker plus a goroutine that survive for the \
             rest of the process. Outside `main` (or a one-shot CLI \
             entrypoint) this accumulates over time."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `time.Tick(d)` with `time.NewTicker(d)` and `defer \
             ticker.Stop()` so the ticker is reclaimed when the function \
             returns. If you genuinely want a process-lifetime ticker, \
             move the call into `main` and document it."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
