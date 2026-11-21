//! `cc.bug.furb_for_else_loop_unused` — Python `for x in items: ...
//! else: cleanup()` where the `else` clause is intended as
//! "loop did not break" but the body has no `break`. The `else` then
//! always runs, defeating the construct's purpose. Most readers
//! misremember `for/else` semantics — having the clause never trigger
//! the documented "did not break" branch is a footgun.
//!
//! Mirrors ruff `B007` cousin / `PLW0120` family pattern.
//!
//! Phase-10 detector: scan every `.py` file once for `for ...:` lines.
//! Walk forward at the same indent looking for an `else:` sibling. If
//! found, scan the loop body for a top-level `break`. If absent, flag.
//!
//! Severity: `Required`. Confidence 0.85 — the scan is indent-aware
//! but does not handle conditional `break` inside helper functions or
//! `match` statements at the same indent.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.furb_for_else_loop_unused`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FurbForElseLoopUnusedRule;

impl Rule for FurbForElseLoopUnusedRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.furb_for_else_loop_unused"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "`for ... else:` clause without `break` in the body — `else` always runs"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
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
    let lines: Vec<&str> = text.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if !is_for_header(line) {
            continue;
        }
        let outer_indent = leading_spaces(line);
        let Some(else_idx) = find_else_sibling(&lines, idx, outer_indent) else {
            continue;
        };
        if !body_has_break(&lines, idx + 1, else_idx, outer_indent) {
            out.push(emit(path.clone(), idx + 1, line));
        }
    }
}

fn is_for_header(line: &str) -> bool {
    let trimmed = line.trim_start();
    (trimmed.starts_with("for ") || trimmed.starts_with("async for "))
        && trimmed.trim_end().ends_with(':')
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

/// Walk forward from the `for:` line looking for an `else:` clause at
/// the same indent. Returns its line index when found.
fn find_else_sibling(lines: &[&str], for_idx: usize, outer_indent: usize) -> Option<usize> {
    for (off, line) in lines.iter().enumerate().skip(for_idx + 1) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_spaces(line);
        if indent < outer_indent {
            return None;
        }
        if indent == outer_indent {
            if trimmed.starts_with("else:") {
                return Some(off);
            }
            return None;
        }
    }
    None
}

/// True iff any line in `[start, end)` has a `break` at indent strictly
/// greater than `outer_indent` (i.e. inside the loop body).
fn body_has_break(lines: &[&str], start: usize, end: usize, outer_indent: usize) -> bool {
    for line in lines.iter().take(end).skip(start) {
        let indent = leading_spaces(line);
        if indent <= outer_indent {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed == "break" || trimmed.starts_with("break ") || trimmed.starts_with("break\t") {
            return true;
        }
    }
    false
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let line_no_u32 = u32::try_from(line_no).unwrap_or(u32::MAX);
    let pos = Position::new(line_no_u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.furb_for_else_loop_unused",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "`for ... else:` body has no `break` — `else` always runs".into(),
        explanation: "Python's `for / else` runs the `else` clause when \
             the loop completed without `break`. Most reviewers \
             misremember the semantics (\"runs when the loop body never \
             executed\") because the official reading is non-obvious. \
             This loop has no `break` in its body, so the `else` clause \
             will always run after the loop — it is structurally \
             equivalent to writing the clause as a follow-up statement \
             at the same indent. The intent is muddled either way: \
             either the author misremembered the semantics, or they \
             added the `else` to signal \"this runs after the loop\" \
             which is confusing without a corresponding `break`."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Either (a) add the `break` that signals the early-exit \
             case the `else` was meant to detect, or (b) drop the \
             `else:` and write the cleanup statements at the same \
             indent as the `for` — they will run unconditionally and \
             the intent will be obvious to every reader."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
