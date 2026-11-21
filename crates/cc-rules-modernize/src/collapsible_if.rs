//! `cc.modernize.collapsible_if` — Python `if a: if b: do()` collapsible
//! into `if a and b: do()`. The nested form adds visual indentation
//! without adding semantic structure.
//!
//! Mirrors ruff `SIM102` (collapsible-if).
//!
//! Phase-9 detector: scan every Python file once. For each `if <a>:`
//! line, look at the next non-comment line; if it is exactly `if <b>:`
//! at one extra indentation level and the outer `if` has no `else:`
//! / `elif:` sibling, flag.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.collapsible_if`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CollapsibleIfRule;

impl Rule for CollapsibleIfRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.collapsible_if"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Python `if a: if b: …` collapsible into `if a and b:`"
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
        if !is_simple_if(line) {
            continue;
        }
        let Some(next) = lines.get(idx + 1) else {
            continue;
        };
        if !is_nested_if(line, next) {
            continue;
        }
        if has_else_sibling(&lines, idx, line) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, line));
    }
}

/// True iff `line` is `<indent>if <cond>:` with nothing trailing.
fn is_simple_if(line: &str) -> bool {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("if ") {
        return false;
    }
    let Some(rest) = trimmed.strip_suffix(':') else {
        return false;
    };
    !rest.contains('#') && !rest.contains(';')
}

/// True iff `next` is an `if` exactly one indentation level deeper than
/// `outer`.
fn is_nested_if(outer: &str, next: &str) -> bool {
    let outer_indent = leading_spaces(outer);
    let next_indent = leading_spaces(next);
    if next_indent <= outer_indent {
        return false;
    }
    let trimmed = next.trim_start();
    if !trimmed.starts_with("if ") {
        return false;
    }
    let Some(rest) = trimmed.strip_suffix(':') else {
        return false;
    };
    !rest.contains('#') && !rest.contains(';')
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

/// Walk forward from `outer_idx` looking for an `else:` / `elif :` at
/// the same indent as the outer `if`. If found, the outer `if` cannot
/// be collapsed without restructuring the alternate branch.
fn has_else_sibling(lines: &[&str], outer_idx: usize, outer: &str) -> bool {
    let outer_indent = leading_spaces(outer);
    for line in lines.iter().skip(outer_idx + 1) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_spaces(line);
        if indent < outer_indent {
            return false;
        }
        if indent == outer_indent {
            return trimmed.starts_with("else:")
                || trimmed.starts_with("elif ")
                || trimmed.starts_with("elif:");
        }
    }
    false
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.collapsible_if",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: "nested `if a: if b:` collapsible into `if a and b:`".into(),
        explanation: "The outer `if` adds an indentation level without \
             adding a branch — there is no `else:` paired with it. \
             Combining the two predicates with `and` reduces vertical \
             noise and surfaces the actual condition at one glance \
             instead of two."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Combine the two predicates with `and`: \
             `if a and b:` then the body. If short-circuit evaluation \
             matters (e.g. `b` is only valid when `a` holds), `and` \
             already gives you the same guarantee — Python evaluates \
             left-to-right and skips `b` when `a` is false."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
