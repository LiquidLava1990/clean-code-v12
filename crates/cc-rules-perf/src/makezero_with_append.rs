//! `cc.perf.makezero_with_append` — Go `s := make([]T, n)` followed by
//! `s = append(s, ...)` (creates n zero values, then grows past them).
//!
//! `make([]T, n)` allocates AND zero-initialises a slice of length `n`.
//! `append(s, ...)` then extends the slice past those zeros, leaving
//! the leading `n` zero-valued entries the caller almost never wanted.
//! The intended idiom is `make([]T, 0, n)` — length zero, capacity
//! `n` — which preallocates the backing array without populating it.
//!
//! OSS source: golangci `makezero` / staticcheck SA4006 (read-then-write
//! variant).
//!
//! Phase-9 source-byte heuristic: `.go` files only. Detect lines of
//! the form `name := make([]T, n)` (no third arg) and verify a later
//! `append(name, ...)` exists in the same function body. Skip
//! `_test.go` for safety.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-MAKEZERO-WITH-APPEND.
#[derive(Debug, Default, Clone, Copy)]
pub struct MakezeroWithAppendRule;

impl Rule for MakezeroWithAppendRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.makezero_with_append"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "make([]T, n) + append leaves n zero-valued items at the start"
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
    for (idx, line) in lines.iter().enumerate() {
        let Some(name) = parse_make_with_length(line) else {
            continue;
        };
        if !any_later_append(&lines[idx + 1..], &name) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, line, &name));
    }
}

/// Match `name := make([]T, n)` (two-arg make — length only). The
/// detector explicitly excludes `make([]T, 0, n)` (correct idiom) and
/// `make(map[K]V, n)` / `make(chan T, n)` (different semantics).
fn parse_make_with_length(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let make_idx = trimmed.find("make([")?;
    let after_make = &trimmed[make_idx..];
    let close_idx = after_make.find(')')?;
    let args = &after_make[..close_idx];
    let arg_count = args.matches(',').count();
    // `make([]T, n)` => one comma between `]T` and `n`. Two commas means three args.
    if arg_count != 1 {
        return None;
    }
    let assign_idx = trimmed.find(":=").or_else(|| trimmed.find('='))?;
    if assign_idx >= make_idx {
        return None;
    }
    let lhs = trimmed[..assign_idx].trim();
    let name: String = lhs
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() || name == "_" {
        None
    } else {
        Some(name)
    }
}

fn any_later_append(later: &[&str], name: &str) -> bool {
    let needle = format!("append({name},");
    let needle_with_space = format!("append({name} ");
    later
        .iter()
        .any(|l| l.contains(&needle) || l.contains(&needle_with_space))
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, name: &str) -> Finding {
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
        rule_id: "cc.perf.makezero_with_append",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "`{name} := make([]T, n)` then `append({name}, ...)` leaves N zero-valued items"
        ),
        explanation: format!(
            "`make([]T, n)` allocates AND zero-initialises a slice of \
             length `n`. The subsequent `append({name}, ...)` then \
             extends the slice past those zeros, so the final value of \
             `{name}` starts with `n` zero entries before the real \
             data. The fix is to preallocate capacity without length: \
             `make([]T, 0, n)`."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Change `make([]T, n)` -> `make([]T, 0, n)`. The `0` is the \
             initial length; the `n` is the capacity hint that lets \
             `append` avoid re-growing the backing array. Final length \
             ends up the same; the leading zeros are gone."
        )),
        snippet,
        weight: 2,
    })
}
