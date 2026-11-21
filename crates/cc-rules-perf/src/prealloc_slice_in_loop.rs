//! `cc.perf.prealloc_slice_in_loop` — Go slice grown in a `for ...
//! range` loop without `make([]T, 0, len(items))` preallocation.
//!
//! Go's `append` reallocates the backing array (typically 2x growth)
//! every time capacity is exhausted, then copies every element to the
//! new buffer. For a known iteration count this is O(N log N) work
//! that can be O(N) with a single up-front allocation:
//!
//! ```go
//! out := make([]Foo, 0, len(items))
//! for _, x := range items {
//!     out = append(out, transform(x))
//! }
//! ```
//!
//! OSS source: golangci `prealloc`.
//!
//! Phase-9 source-byte heuristic: `.go` files only. Detect a
//! `name := []T{}` / `var name []T` / `name := make([]T, 0)` zero-length
//! slice declared immediately above a `for ... range items {` loop
//! that calls `append(name, ...)`. Report the missing capacity hint.
//! Skip `_test.go` for safety.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, find_matching_brace_end, is_go_test_path, looks_like_rule_pack_source,
    PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-PREALLOC-SLICE-IN-LOOP.
#[derive(Debug, Default, Clone, Copy)]
pub struct PreallocSliceInLoopRule;

/// Lookahead window — declarations that birth the slice should sit
/// immediately above the loop in idiomatic Go.
const WINDOW: usize = 4;

impl Rule for PreallocSliceInLoopRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.prealloc_slice_in_loop"
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
        "slice grown in a range-loop without capacity preallocation"
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
    for idx in 0..lines.len() {
        let Some(items_arg) = parse_range_loop(lines[idx]) else {
            continue;
        };
        let lo = idx.saturating_sub(WINDOW);
        let Some((decl_idx, name)) = find_zero_slice_decl(&lines[lo..idx]) else {
            continue;
        };
        let body_end = find_matching_brace_end(&lines, idx);
        if !any_append_in_body(&lines[idx + 1..body_end], &name) {
            continue;
        }
        let line_no = lo + decl_idx + 1;
        out.push(emit(
            path.clone(),
            line_no,
            lines[lo + decl_idx],
            &name,
            &items_arg,
        ));
    }
}

/// Match `for _, x := range items {` and return the iterable name.
fn parse_range_loop(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let after_for = trimmed.strip_prefix("for ")?;
    let range_idx = after_for.find("range ")?;
    let after_range = &after_for[range_idx + 6..];
    let stop = after_range
        .find(|c: char| c == '{' || c == ',' || c.is_whitespace())
        .unwrap_or(after_range.len());
    let name: String = after_range[..stop]
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Search the lookahead window for a zero-length slice declaration.
/// Returns the relative line index + the slice name.
fn find_zero_slice_decl(window: &[&str]) -> Option<(usize, String)> {
    for (rel, line) in window.iter().enumerate().rev() {
        if let Some(name) = parse_zero_slice(line) {
            return Some((rel, name));
        }
    }
    None
}

/// Match the three canonical zero-length slice declarations:
/// - `name := []T{}`
/// - `var name []T`
/// - `name := make([]T, 0)` (no capacity)
fn parse_zero_slice(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    if let Some(name) = parse_var_decl(trimmed) {
        return Some(name);
    }
    if let Some(name) = parse_short_zero(trimmed) {
        return Some(name);
    }
    None
}

fn parse_var_decl(trimmed: &str) -> Option<String> {
    let after_var = trimmed.strip_prefix("var ")?;
    if !after_var.contains("[]") {
        return None;
    }
    if after_var.contains('=') {
        return None; // `var x []T = ...` — initial value provided
    }
    let head = after_var.split_whitespace().next()?;
    Some(head.to_owned())
}

fn parse_short_zero(trimmed: &str) -> Option<String> {
    let assign_idx = trimmed.find(":=")?;
    let lhs = trimmed[..assign_idx].trim();
    let rhs = trimmed[assign_idx + 2..].trim();
    let is_zero_literal = rhs.starts_with("[]") && rhs.contains("{}");
    let is_zero_make = rhs.starts_with("make([]") && rhs.contains(", 0)");
    if !(is_zero_literal || is_zero_make) {
        return None;
    }
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

fn any_append_in_body(body: &[&str], name: &str) -> bool {
    let needle = format!("append({name},");
    body.iter().any(|l| l.contains(&needle))
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, name: &str, items: &str) -> Finding {
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
        rule_id: "cc.perf.prealloc_slice_in_loop",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("slice `{name}` grown in `range {items}` loop without capacity hint"),
        explanation: format!(
            "`append` reallocates the backing array each time capacity \
             runs out (typically doubling, copying every element each \
             time). For a loop whose iteration count is known up front \
             — `range {items}` makes `len({items})` available — that \
             reallocation is wasted work. Preallocating capacity makes \
             the loop a single allocation."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace the zero-length declaration with \
             `{name} := make([]T, 0, len({items}))` so `append` never \
             needs to grow the backing array. The final length is the \
             same; only the allocation profile changes."
        )),
        snippet,
        weight: 2,
    })
}
