//! `cc.concurrent.context_no_propagate` — Go function with `ctx
//! context.Context` parameter that calls a child with
//! `context.Background()` / `context.TODO()` instead of `ctx`.
//!
//! Context propagation is the only mechanism Go services have for
//! deadline / cancellation flow. A function that accepts `ctx` then
//! drops it on the floor (passing a fresh `context.Background()` to
//! every downstream call) creates an unkillable subtree: the parent
//! request can be cancelled, but the children continue until they
//! finish naturally. The classic symptom is a service that holds a
//! request goroutine for ~30 seconds after the client disconnected.
//!
//! OSS source: golangci `contextcheck`.
//!
//! Phase-9 source-byte heuristic: `.go` files only. For each function
//! whose parameter list contains `context.Context`, scan the body for
//! `context.Background(` / `context.TODO(` calls and flag them. Skip
//! `_test.go` for safety.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, collect_function_ranges, is_go_test_path, looks_like_rule_pack_source,
    ConcurrencyFindingBlueprint,
};

/// Family-5 probe R-CONTEXT-NO-PROPAGATE.
#[derive(Debug, Default, Clone, Copy)]
pub struct ContextNoPropagateRule;

const FRESH_CONTEXT_NEEDLES: &[&str] = &["context.Background(", "context.TODO("];

impl Rule for ContextNoPropagateRule {
    fn rule_id(&self) -> &'static str {
        "cc.concurrent.context_no_propagate"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Concurrent
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "context.Background()/TODO() inside a function that already has ctx"
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
    let lines: Vec<&str> = text.lines().collect();
    let func_ranges = collect_function_ranges(&lines, |l| l.contains("context.Context"));
    for (start, end) in func_ranges {
        scan_function_for_fresh_ctx(&lines, start, end, path, out);
    }
}

fn scan_function_for_fresh_ctx(
    lines: &[&str],
    start: usize,
    end: usize,
    path: &Utf8PathBuf,
    out: &mut Vec<Finding>,
) {
    for idx in start + 1..end {
        let line = lines[idx];
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let Some(needle) = FRESH_CONTEXT_NEEDLES.iter().find(|n| line.contains(*n)) else {
            continue;
        };
        out.push(emit(path.clone(), idx + 1, line, needle));
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, needle: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    let call = needle.trim_end_matches('(');
    build_finding(ConcurrencyFindingBlueprint {
        rule_id: "cc.concurrent.context_no_propagate",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "`{call}()` used inside a function that already accepts `ctx context.Context`"
        ),
        explanation: format!(
            "The enclosing function accepts a `context.Context` parameter \
             but creates a fresh root context with `{call}()` instead of \
             passing `ctx` to the downstream call. This breaks the \
             cancellation chain: when the caller cancels the parent ctx, \
             the goroutines hanging off the fresh context keep running \
             until they finish naturally. The classic symptom is a \
             service that ignores client disconnects."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Pass the existing `ctx` to the downstream call. If you need \
             to extend the deadline, use `ctx, cancel := \
             context.WithTimeout(ctx, 30*time.Second)` and `defer \
             cancel()` — derive, never replace."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
