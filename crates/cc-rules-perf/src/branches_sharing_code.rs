//! `cc.perf.branches_sharing_code` — `if cond { ... ; shared(); }
//! else { ... ; shared(); }` — common tail across both branches.
//!
//! Canonical pattern:
//! ```text
//! if ready {
//!     prep_a();
//!     log("done");
//! } else {
//!     prep_b();
//!     log("done");
//! }
//! ```
//! Lifting the shared lines out of the branches makes intent explicit
//! ("we always log; only the prep differs") and avoids the maintenance
//! footgun where one branch silently drifts away from the other.
//!
//! OSS source: clippy `branches_sharing_code`.
//!
//! Phase-9 source-byte heuristic: scan `.rs` files for the simple two-
//! branch shape `if <cond> {` ... `} else {` ... `}` confined to a
//! single function-body indent level. When both branches end on an
//! identical non-trivial line (>= 8 chars after trim, not `}`), fire.
//! Skip test files and rule-pack source.
//!
//! Confidence 0.85 — heuristic ignores nested expressions / match arms.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_rust_test_path, looks_like_rule_pack_source, PerfFindingBlueprint,
};

/// Family-2 probe R-BRANCHES-SHARING-CODE.
#[derive(Debug, Default, Clone, Copy)]
pub struct BranchesSharingCodeRule;

/// Window cap — beyond this many lines we don't bother.
const MAX_BRANCH_LINES: usize = 60;
/// Minimum trimmed length for the shared tail to count as meaningful.
const MIN_TAIL_LEN: usize = 8;

impl Rule for BranchesSharingCodeRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.branches_sharing_code"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "if/else branches share an identical tail line"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("rs") {
                continue;
            }
            if is_rust_test_path(&path) || looks_like_rule_pack_source(&path) {
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
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if !is_if_open_line(trimmed) {
            continue;
        }
        if let Some((shared_line, shared_idx)) = find_shared_tail(&lines, idx) {
            out.push(emit(path.clone(), shared_idx + 1, line, &shared_line));
        }
    }
}

fn is_if_open_line(trimmed: &str) -> bool {
    trimmed.starts_with("if ") && trimmed.ends_with('{')
}

/// Walk `if { ... } else { ... }` from `if_line_idx`. Returns the
/// shared tail line (trimmed) and the absolute line index where it
/// appears in the THEN branch.
fn find_shared_tail(lines: &[&str], if_idx: usize) -> Option<(String, usize)> {
    let (then_close_idx, has_else) = find_then_close(lines, if_idx + 1, MAX_BRANCH_LINES)?;
    if !has_else {
        return None;
    }
    let else_end = find_else_end(lines, then_close_idx, MAX_BRANCH_LINES)?;
    let then_tail_idx = last_meaningful_line(lines, if_idx + 1, then_close_idx)?;
    let else_tail_idx = last_meaningful_line(lines, then_close_idx + 1, else_end)?;
    let then_tail = lines.get(then_tail_idx)?.trim();
    let else_tail = lines.get(else_tail_idx)?.trim();
    if then_tail != else_tail {
        return None;
    }
    if then_tail.len() < MIN_TAIL_LEN {
        return None;
    }
    if then_tail == "}" || then_tail.starts_with("//") {
        return None;
    }
    Some((then_tail.to_owned(), then_tail_idx))
}

/// Walk forward from `start` tracking brace depth (start depth = 1 for
/// the open `{` of THEN). Returns `(idx, has_else)` where `idx` is the
/// line containing the closing `}` of the THEN block and `has_else`
/// indicates whether an `else {` appears on the same line.
fn find_then_close(lines: &[&str], start: usize, cap: usize) -> Option<(usize, bool)> {
    let close_idx = walk_to_block_close(lines, start, cap)?;
    let trimmed = lines[close_idx].trim();
    let has_else = trimmed.contains("else") && trimmed.ends_with('{');
    Some((close_idx, has_else))
}

/// Walk forward from the `} else {` line tracking the ELSE block's
/// brace depth. Returns the index of the line containing the closing
/// `}` of the ELSE block.
fn find_else_end(lines: &[&str], else_open_idx: usize, cap: usize) -> Option<usize> {
    walk_to_block_close(lines, else_open_idx + 1, cap)
}

/// Shared brace-walker. Starts at depth 1 (caller has already seen the
/// opening `{` on the previous line), then for each subsequent line
/// processes closes BEFORE opens — so `} else {` correctly drops
/// depth to zero on the closing brace and signals end-of-block.
fn walk_to_block_close(lines: &[&str], start: usize, cap: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let end = (start + cap).min(lines.len());
    for (offset, line) in lines[start..end].iter().enumerate() {
        let opens = i32::try_from(line.matches('{').count()).unwrap_or(0);
        let closes = i32::try_from(line.matches('}').count()).unwrap_or(0);
        depth -= closes;
        if depth <= 0 {
            return Some(start + offset);
        }
        depth += opens;
    }
    None
}

/// Find the last line in `[start, end)` whose trimmed body is not
/// `{`, `}`, blank, or a comment.
fn last_meaningful_line(lines: &[&str], start: usize, end: usize) -> Option<usize> {
    if start >= end {
        return None;
    }
    let upper = end.min(lines.len());
    for idx in (start..upper).rev() {
        let trimmed = lines[idx].trim();
        if trimmed.is_empty() || trimmed == "{" || trimmed == "}" {
            continue;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("} else") {
            continue;
        }
        return Some(idx);
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, shared: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    let display_shared: String = shared.chars().take(120).collect();
    build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.branches_sharing_code",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("if/else branches share trailing line `{display_shared}`"),
        explanation: "Both branches of the `if/else` end with the same line. \
             Lifting it out of the branches makes the shared work \
             explicit and prevents the silent-drift bug where one \
             branch is later edited without the other. The two \
             prep paths can keep their distinct logic; only the \
             tail moves to after the closing `}`."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Move the shared trailing statement out of both branches \
             to immediately after the `if/else` block. Keep only the \
             diverging logic inside the branches."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
