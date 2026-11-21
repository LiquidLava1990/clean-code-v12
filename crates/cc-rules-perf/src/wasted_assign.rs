//! `cc.perf.wasted_assign` — Go `x := <expr>` followed by `x = <expr>`
//! before any read of `x` (the first assignment is dead).
//!
//! ```go
//! x := 1   // <-- wasted: never read before being overwritten
//! x = 2
//! use(x)
//! ```
//!
//! The first store is wasted work — and worse, evidence that the
//! programmer intended `x` to start at `1` for some path that no
//! longer exists. golangci's `wastedassign` catches this; `ineffassign`
//! catches the closely-related "assigned but never read" form.
//!
//! OSS source: golangci `wastedassign` / `ineffassign`.
//!
//! Phase-9 source-byte heuristic: `.go` files only. For each
//! `name := <expr>` line, scan the rest of the enclosing block (until
//! the matching `}`). If the next reference to `name` is a re-assignment
//! (`name = ...` with no usage of `name` on the RHS) before any read,
//! the original `:=` is wasted. Skip `_test.go` for safety.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    apply_braces, build_finding, is_go_test_path, looks_like_rule_pack_source, PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-WASTED-ASSIGN.
#[derive(Debug, Default, Clone, Copy)]
pub struct WastedAssignRule;

impl Rule for WastedAssignRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.wasted_assign"
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
        "value bound by `:=` is overwritten before being read"
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
        let Some(name) = parse_short_decl(lines[idx]) else {
            continue;
        };
        if let Some(rel) = find_dead_overwrite(&lines, idx + 1, &name) {
            out.push(emit(path.clone(), idx + 1, lines[idx], &name, rel));
        }
    }
}

/// Match `name := <expr>` (single-LHS only — multi-return calls like
/// `a, b := f()` are intentional spreads, not wasted). Conservative.
fn parse_short_decl(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let assign_idx = trimmed.find(":=")?;
    let lhs = trimmed[..assign_idx].trim();
    if lhs.contains(',') {
        return None;
    }
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

/// Walk forward looking for `name = <expr>` (no `:=`) where:
/// 1. No read of `name` happens between the original decl and here.
/// 2. The RHS does NOT reference `name` (so it's not a self-update).
/// Stops at the first `}` that pops below depth 0 (escapes the block).
fn find_dead_overwrite(lines: &[&str], start: usize, name: &str) -> Option<u32> {
    let mut depth: i32 = 0;
    for (rel, line) in lines.iter().enumerate().skip(start) {
        depth = apply_braces(depth, line);
        if depth < 0 {
            return None;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let action = classify_line(trimmed, name);
        match action {
            LineAction::DeadOverwrite => {
                return Some(u32::try_from(rel + 1).unwrap_or(u32::MAX));
            }
            LineAction::ReadOrSelfUpdate => return None,
            LineAction::Unrelated => continue,
        }
    }
    None
}

#[derive(Debug)]
enum LineAction {
    DeadOverwrite,
    ReadOrSelfUpdate,
    Unrelated,
}

fn classify_line(trimmed: &str, name: &str) -> LineAction {
    let mentions = word_appears(trimmed, name);
    if !mentions {
        return LineAction::Unrelated;
    }
    if let Some((lhs, rhs)) = split_assignment(trimmed) {
        if lhs.trim() == name && !word_appears(rhs, name) {
            return LineAction::DeadOverwrite;
        }
    }
    LineAction::ReadOrSelfUpdate
}

/// Match `lhs = rhs` (NOT `:=`, NOT `==`, NOT `!=`, etc.). Returns
/// `(lhs, rhs)` slices for the simple cases.
fn split_assignment(trimmed: &str) -> Option<(&str, &str)> {
    let eq_idx = trimmed.find(" = ")?;
    if trimmed[..eq_idx].contains(":=") {
        return None;
    }
    let after_eq = &trimmed[eq_idx + 3..];
    let lhs = trimmed[..eq_idx].trim();
    if lhs.is_empty() {
        return None;
    }
    Some((lhs, after_eq))
}

fn word_appears(haystack: &str, name: &str) -> bool {
    haystack
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| tok == name)
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, name: &str, _rel: u32) -> Finding {
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
        rule_id: "cc.perf.wasted_assign",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{name} := ...` is overwritten before being read"),
        explanation: format!(
            "The initial value bound to `{name}` is dead code: the very \
             next assignment to `{name}` does not read the previous \
             value, so the first store is pure overhead. More \
             importantly, it is evidence of a deleted code path that \
             once cared about the initial value — review the history \
             before removing."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Either delete the wasted `{name} := <expr>` line, or move \
             the real initialisation up so the second assignment is \
             unnecessary. If both branches were intentional, fold them \
             into a single conditional: \
             `{name} := if cond {{ a }} else {{ b }}` (Go: use a \
             helper or a switch statement)."
        )),
        snippet,
        weight: 1,
    })
}
