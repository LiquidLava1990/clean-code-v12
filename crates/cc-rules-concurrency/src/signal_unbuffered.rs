//! `cc.concurrent.signal_unbuffered` — Go `signal.Notify(c, ...)` where
//! `c` was created as `make(chan os.Signal)` (unbuffered).
//!
//! From the `os/signal` documentation:
//!
//! > Package signal will not block sending to c: the caller must ensure
//! > that c has sufficient buffer space to keep up with the expected
//! > signal rate.
//!
//! An unbuffered channel passed to `signal.Notify` silently drops
//! signals — including the `SIGTERM` / `SIGINT` the program was hoping
//! to listen for. Standard idiom is `make(chan os.Signal, 1)`.
//!
//! Phase-7 source-byte heuristic: `.go` files only. Detect
//! `signal.Notify(NAME, ...)` and verify a `make(chan os.Signal)` (no
//! buffer) earlier in the file binds to `NAME`.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, ConcurrencyFindingBlueprint,
};

/// Family-5 probe R-SIGNAL-UNBUFFERED.
#[derive(Debug, Default, Clone, Copy)]
pub struct SignalUnbufferedRule;

const NOTIFY_NEEDLE: &str = "signal.Notify(";
const UNBUFFERED_MAKE: &str = "make(chan os.Signal)";

impl Rule for SignalUnbufferedRule {
    fn rule_id(&self) -> &'static str {
        "cc.concurrent.signal_unbuffered"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Concurrent
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "signal.Notify on an unbuffered channel silently drops signals"
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
            if is_go_test_path(&path) || looks_like_rule_pack_source(&path) {
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
    let unbuffered_names = collect_unbuffered_signal_channels(text);
    if unbuffered_names.is_empty() {
        return;
    }
    for (line_idx, line) in text.lines().enumerate() {
        let Some(arg) = extract_notify_first_arg(line) else {
            continue;
        };
        if unbuffered_names.iter().any(|n| n == &arg) {
            out.push(emit(path.clone(), line_idx + 1, line, &arg));
        }
    }
}

fn collect_unbuffered_signal_channels(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        if !line.contains(UNBUFFERED_MAKE) {
            continue;
        }
        if let Some(name) = parse_lhs_identifier(line) {
            out.push(name);
        }
    }
    out
}

/// Heuristic: parse `name := make(chan os.Signal)` /
/// `var name = make(chan os.Signal)` and return `name`.
fn parse_lhs_identifier(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let head = trimmed.strip_prefix("var ").unwrap_or(trimmed);
    let assign_idx = head.find(":=").or_else(|| head.find('='))?;
    let lhs = head[..assign_idx].trim();
    let name: String = lhs
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn extract_notify_first_arg(line: &str) -> Option<String> {
    let idx = line.find(NOTIFY_NEEDLE)?;
    let after = &line[idx + NOTIFY_NEEDLE.len()..];
    let arg: String = after
        .chars()
        .take_while(|c| !matches!(c, ',' | ')' | ' '))
        .collect();
    if arg.is_empty() {
        None
    } else {
        Some(arg)
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, arg: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ConcurrencyFindingBlueprint {
        rule_id: "cc.concurrent.signal_unbuffered",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`signal.Notify` on unbuffered channel `{arg}` silently drops signals"),
        explanation: format!(
            "`{arg}` was created with `make(chan os.Signal)` (no buffer). The \
             `os/signal` package documents that it will NOT block sending to \
             the channel — if the receiver is slow, signals are dropped on \
             the floor. The most common visible symptom is a program that \
             ignores Ctrl-C the second time it is sent."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Allocate a buffered channel: `{arg} := make(chan os.Signal, 1)`. \
             A buffer of 1 is enough for graceful-shutdown patterns. For \
             listeners that need to coalesce many signals, size the buffer \
             to the burst rate."
        )),
        snippet,
        weight: 4,
    })
}
