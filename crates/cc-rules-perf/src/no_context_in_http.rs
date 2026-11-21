//! `cc.perf.no_context_in_http` — Go `http.NewRequest(...)` (no
//! context) inside a function that already has a `ctx context.Context`
//! parameter.
//!
//! `http.NewRequest` creates a request with no associated context, so
//! the request cannot be cancelled by the caller's deadline. The
//! contextual variant `http.NewRequestWithContext(ctx, method, url,
//! body)` threads the cancellation chain through the HTTP transport.
//! For services on a request budget — most modern Go services — using
//! the non-contextual variant is a reliability foot-gun: a slow
//! upstream blocks the request goroutine indefinitely.
//!
//! OSS source: golangci `noctx`.
//!
//! Phase-9 source-byte heuristic: `.go` files only. Detect lines
//! calling `http.NewRequest(` inside the body of a function whose
//! parameter list contains `context.Context`. Skip `_test.go` for
//! safety.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, collect_function_ranges, is_go_test_path, looks_like_rule_pack_source,
    PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-NO-CONTEXT-IN-HTTP.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoContextInHttpRule;

const NEW_REQUEST: &str = "http.NewRequest(";

impl Rule for NoContextInHttpRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.no_context_in_http"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "http.NewRequest used where http.NewRequestWithContext belongs"
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
        for idx in start + 1..end {
            let line = lines[idx];
            if line.trim_start().starts_with("//") {
                continue;
            }
            if !line.contains(NEW_REQUEST) {
                continue;
            }
            if line.contains("http.NewRequestWithContext(") {
                continue;
            }
            out.push(emit(path.clone(), idx + 1, line));
        }
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.no_context_in_http",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline:
            "`http.NewRequest` discards the function's ctx — use `http.NewRequestWithContext`"
                .into(),
        explanation: "The enclosing function accepts `ctx context.Context` but \
             `http.NewRequest` creates a request with no context, so \
             the HTTP transport cannot honour the caller's deadline or \
             cancellation. Slow upstreams block the request goroutine \
             indefinitely; the calling service's request-budget \
             collapses under the slowest dependency."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace `http.NewRequest(method, url, body)` with \
             `http.NewRequestWithContext(ctx, method, url, body)`. The \
             signatures are otherwise identical; the contextual variant \
             threads cancellation through `(*Client).Do`."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
