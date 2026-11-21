//! `cc.modernize.unnecessary_lazy_evaluations` — `unwrap_or_else(|| <lit>)`,
//! `or_else(|| Some(<lit>))`, `map_or_else(|| <lit>, …)` etc.
//!
//! Canonical pattern:
//! ```text
//! cfg.timeout.unwrap_or_else(|| 30);             // -> unwrap_or(30)
//! cache.get(&id).or_else(|| Some("fallback"));   // -> or(Some("fallback"))
//! some_opt.map_or_else(|| 0, len);                // -> map_or(0, len)
//! ```
//! The `_else` variants exist so the fallback can be lazy when it is
//! expensive or fallible. When the closure body is just a literal /
//! constant, the laziness buys nothing — and the closure adds an
//! extra type-erasure step the optimiser has to chew through. Each
//! has an eager twin (`unwrap_or` / `or` / `map_or`) that takes the
//! value directly.
//!
//! OSS source: clippy `unnecessary_lazy_evaluations`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files for
//! `.unwrap_or_else(|| <lit>)`, `.or_else(|| Some(<lit>))`, and
//! `.map_or_else(|| <lit>, ...)` where `<lit>` is a number, string,
//! bool, or path-call constant. Skip test files and rule-pack source.
//!
//! Severity `Nit`, confidence 0.9.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.unnecessary_lazy_evaluations`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnnecessaryLazyEvaluationsRule;

const NEEDLES: &[(&str, &str, &str)] = &[
    (".unwrap_or_else(|| ", ".unwrap_or", "unwrap_or"),
    (".or_else(|| Some(", ".or(Some(", "or"),
    (".map_or_else(|| ", ".map_or", "map_or"),
];

impl Rule for UnnecessaryLazyEvaluationsRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.unnecessary_lazy_evaluations"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "lazy `_else` combinator with a literal fallback could be the eager twin"
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
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some((kind, eager_form)) = detect_lazy_with_literal(line) {
            out.push(emit(path.clone(), idx + 1, line, kind, eager_form));
        }
    }
}

/// Returns `(combinator_name, eager_replacement)` when the line uses
/// a lazy combinator with a literal fallback.
fn detect_lazy_with_literal(line: &str) -> Option<(&'static str, &'static str)> {
    for (lazy, eager, kind) in NEEDLES {
        let Some(idx) = line.find(lazy) else {
            continue;
        };
        let after = &line[idx + lazy.len()..];
        if first_token_is_literal(after) {
            return Some((kind, eager));
        }
    }
    None
}

/// True when the leading expression in `s` is a simple literal —
/// number, string, bool, char, or `None`.
fn first_token_is_literal(s: &str) -> bool {
    let trimmed = s.trim_start();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let first = bytes[0];
    if first == b'"' || first == b'\'' {
        return true;
    }
    if first.is_ascii_digit() || first == b'-' || first == b'+' {
        return is_number_then_terminator(trimmed);
    }
    for keyword in ["true", "false", "None"] {
        if let Some(rest) = trimmed.strip_prefix(keyword) {
            if rest.starts_with(|c: char| !c.is_ascii_alphanumeric() && c != '_') || rest.is_empty()
            {
                return true;
            }
        }
    }
    false
}

fn is_number_then_terminator(s: &str) -> bool {
    let mut iter = s.char_indices();
    let mut last = 0_usize;
    let mut saw_digit = false;
    for (i, c) in iter.by_ref() {
        if c == '-' || c == '+' {
            if i != 0 {
                break;
            }
            last = i + c.len_utf8();
            continue;
        }
        if c.is_ascii_digit() {
            saw_digit = true;
            last = i + c.len_utf8();
            continue;
        }
        if c == '_' || c == '.' {
            last = i + c.len_utf8();
            continue;
        }
        if c.is_ascii_alphabetic() {
            // numeric type suffix like `5u32` — accept and stop.
            saw_digit = true;
            last = i + c.len_utf8();
            continue;
        }
        break;
    }
    let _ = last;
    saw_digit
}

fn emit(
    path: Utf8PathBuf,
    line_no: usize,
    line: &str,
    kind: &'static str,
    eager_form: &'static str,
) -> Finding {
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
        rule_id: "cc.modernize.unnecessary_lazy_evaluations",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`.{kind}_else(|| <lit>)` is just `{eager_form}(<lit>)`"),
        explanation: "The `_else` combinators (`unwrap_or_else`, `or_else`, \
             `map_or_else`) exist so the fallback can be lazy — \
             useful when computing it is expensive or fallible. When \
             the closure body is just a literal, laziness buys \
             nothing and the optimiser still has to chew through one \
             extra type-erasure layer. The eager twin takes the \
             value directly with the same final code."
            .into(),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace the `_else` form with the eager twin: \
                 `{eager_form}(<lit>)` directly. Reserve `_else` for \
                 fallbacks that genuinely need the closure (allocation, \
                 fallible computation, side-effecting log)."
        )),
        snippet,
        weight: 1,
    })
}
