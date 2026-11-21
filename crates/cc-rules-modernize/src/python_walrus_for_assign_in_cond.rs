//! `cc.modernize.python_walrus_for_assign_in_cond` — Python pattern
//! `x = compute(); if x ...:` that could collapse to `if (x := compute()) ...:`.
//!
//! ```python
//! # Before
//! x = compute_thing()
//! if x > 0:
//!     ...
//!
//! # After (Python 3.8+)
//! if (x := compute_thing()) > 0:
//!     ...
//! ```
//! The walrus operator (PEP 572) was added in Python 3.8 and lets the
//! computation and the test live on a single line. This is an
//! opinion-tier nudge — the un-walrus form is still valid — so the
//! probe stays low confidence and Severity::Nit.
//!
//! OSS source: ruff `SIM117` / hand-rolled refactor playbooks. PEP 572.
//!
//! Phase-12 source-byte heuristic: `.py` files only. Match every
//! adjacent pair of lines:
//! - line N:   `<name> = <call>(...)`
//! - line N+1: `if <name> <op> ...:` (where `<name>` is read but not
//!   shadowed within the rest of the if-body)
//!
//! Where `<name>` only appears in the if-condition, NOT inside the
//! body — that's the case where walrus is clearly cleaner.
//!
//! Severity::Nit, confidence 0.7 (opinion-tier).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.python_walrus_for_assign_in_cond`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PythonWalrusForAssignInCondRule;

impl Rule for PythonWalrusForAssignInCondRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.python_walrus_for_assign_in_cond"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "`x = compute(); if x ...` could be `if (x := compute()) ...` (PEP 572)"
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
    if lines.len() < 2 {
        return;
    }
    for idx in 0..lines.len() - 1 {
        let Some((name, indent)) = parse_simple_assign(lines[idx]) else {
            continue;
        };
        if !line_is_if_using(lines[idx + 1], &name, indent) {
            continue;
        }
        if !var_unused_after_if(&lines, idx + 2, &name, indent) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, lines[idx], &name));
    }
}

/// Match `<name> = <call>(...)` on a single line. Returns the bound
/// name and the indent column (whitespace count). Rejects: tuple
/// targets, augmented assigns, type-annotated assigns, no-call RHS.
fn parse_simple_assign(line: &str) -> Option<(String, usize)> {
    let indent = line
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    let trimmed = &line[indent..];
    if trimmed.starts_with('#') {
        return None;
    }
    let eq_idx = trimmed.find(" = ")?;
    let lhs = &trimmed[..eq_idx];
    let rhs = trimmed[eq_idx + 3..].trim();
    if lhs.contains(',') || lhs.contains(':') || lhs.contains('.') || lhs.contains('[') {
        return None;
    }
    let name = lhs.trim();
    if !is_simple_ident(name) {
        return None;
    }
    if !rhs_looks_like_call(rhs) {
        return None;
    }
    Some((name.to_owned(), indent))
}

fn is_simple_ident(s: &str) -> bool {
    !s.is_empty()
        && !s.as_bytes()[0].is_ascii_digit()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn rhs_looks_like_call(rhs: &str) -> bool {
    let mut saw_alpha = false;
    for b in rhs.bytes() {
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' {
            saw_alpha = true;
            continue;
        }
        if b == b'(' && saw_alpha {
            return true;
        }
        if !saw_alpha {
            return false;
        }
        return false;
    }
    false
}

/// True iff `line` is `if <name> <op>...:` at the same indent as the
/// preceding assign.
fn line_is_if_using(line: &str, name: &str, indent: usize) -> bool {
    let line_indent = line
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    if line_indent != indent {
        return false;
    }
    let trimmed = &line[indent..];
    let Some(rest) = trimmed.strip_prefix("if ") else {
        return false;
    };
    let Some(colon_idx) = rest.rfind(':') else {
        return false;
    };
    let cond = &rest[..colon_idx];
    word_appears(cond, name)
}

/// Walk forward from `start` while indent > `if_indent`. Return true
/// iff `name` does NOT appear in the body of the if. Conservative —
/// stops at first dedent.
fn var_unused_after_if(lines: &[&str], start: usize, name: &str, if_indent: usize) -> bool {
    for line in lines.iter().skip(start) {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line
            .bytes()
            .take_while(|b| *b == b' ' || *b == b'\t')
            .count();
        if indent <= if_indent {
            return true;
        }
        if word_appears(line, name) {
            return false;
        }
    }
    true
}

fn word_appears(haystack: &str, name: &str) -> bool {
    haystack
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| tok == name)
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
    build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.python_walrus_for_assign_in_cond",
        severity: Severity::Nit,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{name} = ...; if {name} ...:` could be `if ({name} := ...) ...:`"),
        explanation: format!(
            "Python 3.8 introduced the walrus operator (PEP 572) so the \
             test condition can compute and bind in one expression. \
             Where `{name}` is only read inside the if-condition (and \
             not inside the if-body), the walrus form removes the \
             dangling binding from the surrounding scope and reads \
             slightly cleaner. Opinion-tier: the un-walrus form is \
             perfectly fine — flag and let the reviewer decide."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Collapse to `if ({name} := ...) <op> ...:`. The binding \
             still exists inside the if-body if you need it. If `{name}` \
             is read after the if-block, prefer the un-walrus form for \
             clarity."
        )),
        snippet,
        weight: 1,
    })
}
