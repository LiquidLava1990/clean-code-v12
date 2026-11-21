//! `cc.concurrent.copy_loop_var` — Go `for _, v := range items {
//! go func() { use(v) }() }` capturing the loop variable by reference.
//!
//! Pre-Go-1.22 the `for _, v := range items` loop reused the same `v`
//! storage across iterations, so the closure spawned in the goroutine
//! captured a pointer to the live cursor. By the time the goroutine
//! ran, `v` had advanced — every spawned goroutine saw the same
//! (final) item. Go 1.22 changed the semantics so each iteration gets
//! its own `v`, BUT modules pinned to older `go` directives still
//! exhibit the bug. The portable fix is `v := v` immediately inside
//! the loop body.
//!
//! OSS source: golangci `copyloopvar` / `exportloopref`.
//!
//! Phase-9 source-byte heuristic: `.go` files only. Detect a `for ...
//! range` line that introduces named loop variables, followed (within
//! the loop body) by `go func()` whose body references the loop
//! variable WITHOUT a preceding `var := var` shadowing line. Skip
//! `_test.go` for safety.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, ConcurrencyFindingBlueprint,
};

/// Family-5 probe R-COPY-LOOP-VAR.
#[derive(Debug, Default, Clone, Copy)]
pub struct CopyLoopVarRule;

impl Rule for CopyLoopVarRule {
    fn rule_id(&self) -> &'static str {
        "cc.concurrent.copy_loop_var"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Concurrent
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "goroutine captures range-loop variable by reference"
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
    for hit in find_capture_hits(&lines) {
        out.push(emit(path.clone(), hit));
    }
}

#[derive(Debug)]
struct Hit {
    line_no: u32,
    snippet: String,
    var_name: String,
}

fn find_capture_hits(lines: &[&str]) -> Vec<Hit> {
    let mut out: Vec<Hit> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let Some(loop_vars) = parse_for_range_vars(line) else {
            continue;
        };
        let body_end = find_block_end(lines, idx);
        scan_loop_for_capture(lines, idx + 1, body_end, &loop_vars, &mut out);
    }
    out
}

/// Parse `for _, v := range items` / `for i, v := range items` and
/// return the named loop variables (excluding `_`).
fn parse_for_range_vars(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim_start();
    let after_for = trimmed.strip_prefix("for ")?;
    let assign_idx = after_for.find(":=")?;
    let range_idx = after_for.find("range ")?;
    if assign_idx >= range_idx {
        return None;
    }
    let lhs = after_for[..assign_idx].trim();
    let names: Vec<String> = lhs
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty() && *t != "_")
        .map(str::to_owned)
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// Find the line that closes the `{` opened on `start_idx` (or right
/// after). Delegates to the shared brace tracker in `helpers`.
fn find_block_end(lines: &[&str], start_idx: usize) -> usize {
    crate::helpers::find_matching_brace_end(lines, start_idx)
}

fn scan_loop_for_capture(
    lines: &[&str],
    start: usize,
    end: usize,
    loop_vars: &[String],
    out: &mut Vec<Hit>,
) {
    let mut depth: i32 = 0;
    let mut goroutine_depth: i32 = -1;
    let mut shadowed: Vec<bool> = vec![false; loop_vars.len()];
    for idx in start..end {
        let line = lines[idx];
        update_shadow_state(line, loop_vars, &mut shadowed);
        let next = advance_goroutine_depth(line, depth, goroutine_depth);
        depth = next.0;
        goroutine_depth = next.1;
        if goroutine_depth < 0 {
            continue;
        }
        if let Some(name) = first_unshadowed_match(line, loop_vars, &shadowed) {
            out.push(Hit {
                line_no: u32::try_from(idx + 1).unwrap_or(u32::MAX),
                snippet: line.trim().chars().take(180).collect(),
                var_name: name,
            });
            return;
        }
    }
}

/// One-step state transition for the goroutine-depth tracker. Returns
/// `(new_depth, new_goroutine_depth)`.
fn advance_goroutine_depth(line: &str, depth: i32, goroutine_depth: i32) -> (i32, i32) {
    let mut gd = goroutine_depth;
    if line.contains("go func") && gd < 0 {
        gd = depth;
    }
    let new_depth = crate::helpers::apply_braces(depth, line);
    if gd >= 0 && new_depth <= gd {
        gd = -1;
    }
    (new_depth, gd)
}

fn first_unshadowed_match(line: &str, loop_vars: &[String], shadowed: &[bool]) -> Option<String> {
    for (vi, name) in loop_vars.iter().enumerate() {
        if shadowed[vi] {
            continue;
        }
        if word_appears(line, name) {
            return Some(name.clone());
        }
    }
    None
}

fn update_shadow_state(line: &str, loop_vars: &[String], shadowed: &mut [bool]) {
    for (vi, name) in loop_vars.iter().enumerate() {
        let pat = format!("{name} := {name}");
        if line.contains(&pat) {
            shadowed[vi] = true;
        }
    }
}

/// True iff `name` appears as a standalone word in `line` (rough — the
/// detector is conservative; standalone identifiers are sufficient for
/// the canonical bug shape).
fn word_appears(line: &str, name: &str) -> bool {
    line.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| tok == name)
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
    build_finding(ConcurrencyFindingBlueprint {
        rule_id: "cc.concurrent.copy_loop_var",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "goroutine captures range-loop variable `{}` by reference",
            hit.var_name
        ),
        explanation: format!(
            "Pre-Go-1.22 modules reuse the same storage for `{var}` \
             across iterations. The goroutine's closure captures the \
             address, not the value, so by the time the spawned \
             goroutine runs, `{var}` has advanced (or finished). Every \
             spawned goroutine then sees the same final value — usually \
             the last item in the range, but with no guarantees.",
            var = hit.var_name
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Add `{var} := {var}` as the first line inside the loop body \
             to shadow the loop variable with an iteration-local copy. \
             Or pass `{var}` as an argument: `go func(v T) {{ use(v) }}({var})`. \
             Go 1.22+ fixes the underlying semantics — bump your `go` \
             directive in `go.mod` if you control the module.",
            var = hit.var_name
        )),
        snippet: hit.snippet,
        weight: 5,
    })
}
