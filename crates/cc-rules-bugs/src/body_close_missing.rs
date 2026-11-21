//! `cc.bug.body_close_missing` — Go HTTP response without
//! `defer resp.Body.Close()`.
//!
//! `http.Get` / `http.Post` / `http.PostForm` / `(*Client).Do` /
//! `http.DefaultClient.Do` all return `*http.Response`. The contract
//! says the caller MUST close `resp.Body` — failing to do so leaks the
//! underlying TCP connection (the transport keeps it pinned, never
//! returning it to the idle pool). On a hot path that exhausts the
//! file-descriptor table within minutes.
//!
//! OSS source: golangci `bodyclose`.
//!
//! Phase-9 source-byte heuristic: `.go` files only. Scan every function
//! body for an `http.Get(` / `http.Post(` / `http.PostForm(` / `.Do(`
//! call whose result is bound (`resp, err :=` or `resp :=`); inside the
//! same function body, require a matching `defer <name>.Body.Close()`
//! (or `defer <name>.Body.Close()` after a `nil` check). Skip
//! `_test.go` for safety — future ratchet may opt-in.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, collect_function_ranges, is_go_test_path, looks_like_rule_pack_source,
    BugFindingBlueprint,
};

/// Family-3 probe R-BODY-CLOSE-MISSING.
#[derive(Debug, Default, Clone, Copy)]
pub struct BodyCloseMissingRule;

/// HTTP-call needles whose result returns `*http.Response`.
const HTTP_CALL_NEEDLES: &[&str] = &[
    "http.Get(",
    "http.Post(",
    "http.PostForm(",
    "http.Head(",
    "http.DefaultClient.Do(",
    "client.Do(",
    ".Do(",
];

impl Rule for BodyCloseMissingRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.body_close_missing"
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
        "*http.Response without `defer resp.Body.Close()` leaks the connection"
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
    for hit in find_unclosed_responses(text) {
        out.push(emit(path.clone(), hit));
    }
}

#[derive(Debug)]
struct Hit {
    line_no: u32,
    snippet: String,
    binding: String,
}

/// Walk the file tracking the enclosing function body. For every line
/// that introduces a `*http.Response` binding, require a matching
/// `defer <binding>.Body.Close()` somewhere later in the same function.
fn find_unclosed_responses(text: &str) -> Vec<Hit> {
    let mut out: Vec<Hit> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let func_ranges = collect_function_ranges(&lines, |_| true);
    for (start, end) in func_ranges {
        scan_function_body(&lines, start, end, &mut out);
    }
    out
}

fn scan_function_body(lines: &[&str], start: usize, end: usize, out: &mut Vec<Hit>) {
    let body = &lines[start..end];
    for (idx, line) in body.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let Some(binding) = parse_response_binding(trimmed) else {
            continue;
        };
        if has_close_for(body, &binding) {
            continue;
        }
        out.push(Hit {
            line_no: u32::try_from(start + idx + 1).unwrap_or(u32::MAX),
            snippet: line.trim().chars().take(180).collect(),
            binding,
        });
    }
}

/// Parse `name, err := http.Get(...)` / `name := http.Get(...)` and
/// return `name` when the RHS contains an HTTP-call needle.
fn parse_response_binding(trimmed: &str) -> Option<String> {
    if !HTTP_CALL_NEEDLES.iter().any(|n| trimmed.contains(*n)) {
        return None;
    }
    let assign_idx = trimmed.find(":=").or_else(|| trimmed.find('='))?;
    let lhs = trimmed[..assign_idx].trim();
    let first: String = lhs
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if first.is_empty() || first == "_" {
        None
    } else {
        Some(first)
    }
}

fn has_close_for(body: &[&str], binding: &str) -> bool {
    let close_needle = format!("{binding}.Body.Close()");
    body.iter().any(|l| l.contains(&close_needle))
}

fn emit(path: Utf8PathBuf, hit: Hit) -> Finding {
    let pos = Position::new(hit.line_no, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.body_close_missing",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "HTTP response `{}` is missing `defer {}.Body.Close()`",
            hit.binding, hit.binding
        ),
        explanation: format!(
            "`{}` holds a `*http.Response`. Its `Body` is a live network \
             reader — failing to close it pins the underlying TCP \
             connection, the transport never returns the connection to \
             the idle pool, and the file-descriptor table fills up. The \
             contract from `net/http` is explicit: callers must close \
             `Body` even on error returns.",
            hit.binding
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Immediately after the call (and after the `if err != nil` \
             early-return) add `defer {}.Body.Close()`. For request \
             bodies you also intend to drain, follow with \
             `io.Copy(io.Discard, {}.Body)` before the close so the \
             connection can be reused.",
            hit.binding, hit.binding
        )),
        snippet: hit.snippet,
        weight: 4,
    })
}
