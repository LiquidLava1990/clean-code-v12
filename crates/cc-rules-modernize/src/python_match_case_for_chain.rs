//! `cc.modernize.python_match_case_for_chain` — Python `if/elif` chain
//! testing the same variable against ≥3 distinct values.
//!
//! ```python
//! if status == "open":
//!     handle_open()
//! elif status == "closed":
//!     handle_closed()
//! elif status == "pending":
//!     handle_pending()
//! ```
//! Python 3.10 (PEP 634) introduced `match`/`case`, which compresses
//! the same dispatch into:
//! ```python
//! match status:
//!     case "open":    handle_open()
//!     case "closed":  handle_closed()
//!     case "pending": handle_pending()
//! ```
//! The match form admits structural patterns (tuple destructure, guard
//! conditions, OR-patterns) the `if`/`elif` chain cannot express.
//! Severity::Nit because the existing chain is correct — this is a
//! "consider the modern form" prompt.
//!
//! OSS source: PEP 634, ruff `PLR1714` adjacent.
//!
//! Phase-12 source-byte heuristic: `.py` files only. Find every line
//! `if <name> == <lit>:`, then count consecutive `elif <name> == <lit>:`
//! lines at the same indent. Three or more matches on the same `<name>`
//! triggers the probe.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.python_match_case_for_chain`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PythonMatchCaseForChainRule;

const MIN_CHAIN_LEN: usize = 3;

impl Rule for PythonMatchCaseForChainRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.python_match_case_for_chain"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.8)
    }
    fn description(&self) -> &'static str {
        "≥3-arm `if/elif` chain on the same variable — consider `match`/`case`"
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
    let mut idx = 0;
    while idx < lines.len() {
        let Some((name, indent)) = parse_if_eq_lit(lines[idx]) else {
            idx += 1;
            continue;
        };
        let chain_len = count_elif_chain(&lines, idx + 1, &name, indent);
        if chain_len + 1 >= MIN_CHAIN_LEN {
            out.push(emit(
                path.clone(),
                idx + 1,
                lines[idx],
                &name,
                chain_len + 1,
            ));
            idx += chain_len + 1;
        } else {
            idx += 1;
        }
    }
}

/// Match `if <name> == <lit>:` at start of line. Returns
/// (name, indent_column).
fn parse_if_eq_lit(line: &str) -> Option<(String, usize)> {
    parse_test_eq_lit(line, "if ")
}

/// Match `elif <name> == <lit>:` at start of line. Returns name.
fn parse_elif_eq_lit(line: &str, expected_indent: usize) -> Option<String> {
    let line_indent = line
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    if line_indent != expected_indent {
        return None;
    }
    parse_test_eq_lit(line, "elif ").map(|(n, _)| n)
}

fn parse_test_eq_lit(line: &str, prefix: &str) -> Option<(String, usize)> {
    let indent = line
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count();
    let trimmed = &line[indent..];
    if trimmed.starts_with('#') {
        return None;
    }
    let rest = trimmed.strip_prefix(prefix)?;
    let colon_idx = rest.rfind(':')?;
    let cond = &rest[..colon_idx];
    let eq_idx = cond.find(" == ")?;
    let lhs = cond[..eq_idx].trim();
    let rhs = cond[eq_idx + 4..].trim();
    if !is_simple_ident(lhs) {
        return None;
    }
    if !is_literal(rhs) {
        return None;
    }
    Some((lhs.to_owned(), indent))
}

fn is_simple_ident(s: &str) -> bool {
    !s.is_empty()
        && !s.as_bytes()[0].is_ascii_digit()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// True for string / number / bool / None literals. Conservative — any
/// literal-looking token is fine; the cost of a false positive on this
/// Severity::Nit probe is low.
fn is_literal(s: &str) -> bool {
    if s == "None" || s == "True" || s == "False" {
        return true;
    }
    if let Some(first) = s.as_bytes().first() {
        if matches!(first, b'"' | b'\'') {
            return s.ends_with(*first as char);
        }
        if first.is_ascii_digit() || *first == b'-' {
            return s.bytes().all(|b| {
                b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_' || b == b'e' || b == b'E'
            });
        }
    }
    false
}

fn count_elif_chain(lines: &[&str], start: usize, name: &str, indent: usize) -> usize {
    let mut count: usize = 0;
    let mut idx = start;
    while idx < lines.len() {
        // Skip the body of the previous arm: anything indented deeper than `indent`
        while idx < lines.len() && {
            let l = lines[idx];
            l.trim().is_empty()
                || l.bytes().take_while(|b| *b == b' ' || *b == b'\t').count() > indent
        } {
            idx += 1;
        }
        if idx >= lines.len() {
            break;
        }
        let Some(elif_name) = parse_elif_eq_lit(lines[idx], indent) else {
            break;
        };
        if elif_name != name {
            break;
        }
        count += 1;
        idx += 1;
    }
    count
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, name: &str, arms: usize) -> Finding {
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
        rule_id: "cc.modernize.python_match_case_for_chain",
        severity: Severity::Nit,
        confidence: Confidence::new(0.8),
        location,
        headline: format!(
            "{arms}-arm `if/elif` chain on `{name}` — consider `match {name}: case ...`"
        ),
        explanation: format!(
            "Python 3.10 (PEP 634) added structural pattern matching. \
             A {arms}-arm chain of `{name} == <literal>` tests is the \
             canonical case the new syntax was designed for. The \
             `match` form: (1) reads as a single dispatch instead of a \
             telescoping chain, (2) admits OR-patterns (`case \"a\" \
             | \"b\":`), guard conditions (`case x if x > 0:`), and \
             structural destructuring on tuples / dataclasses / \
             dict-shapes that `if`/`elif` cannot express, (3) lets \
             linters and type-checkers verify exhaustiveness."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Rewrite as `match {name}:` with one `case <literal>:` arm \
             per `elif`. Use `case _:` for the trailing `else` if any. \
             Requires Python 3.10+; if you need 3.9 compatibility keep \
             the chain (linter will skip on language-version pin)."
        )),
        snippet,
        weight: 1,
    })
}
