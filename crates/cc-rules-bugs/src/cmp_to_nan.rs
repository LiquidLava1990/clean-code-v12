//! `cc.bug.cmp_to_nan` — direct equality comparison against `NaN`.
//!
//! `NaN != NaN` by IEEE-754 definition, so any of these expressions
//! produces a constant the author did not intend:
//!
//! - Python: `x == float("nan")`, `x != float("nan")`
//! - JS / TS: `x === NaN`, `x !== NaN`, `x === Number.NaN`
//! - Rust: `x == f64::NAN`, `x != f64::NAN`
//! - Go: `x == math.NaN()`, `x != math.NaN()`
//!
//! Phase-7 heuristic: per-line source-byte scan over every file in the
//! batch. Skips test files and rule-pack source.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-CMP-TO-NAN.
#[derive(Debug, Default, Clone, Copy)]
pub struct CmpToNanRule;

const NAN_NEEDLES: &[&str] = &[
    "== NaN",
    "!= NaN",
    "=== NaN",
    "!== NaN",
    "== Number.NaN",
    "!= Number.NaN",
    "=== Number.NaN",
    "!== Number.NaN",
    "== f64::NAN",
    "!= f64::NAN",
    "== f32::NAN",
    "!= f32::NAN",
    "== math.NaN()",
    "!= math.NaN()",
    "== float(\"nan\")",
    "!= float(\"nan\")",
    "== float('nan')",
    "!= float('nan')",
];

impl Rule for CmpToNanRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.cmp_to_nan"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "equality comparison against NaN — always evaluates to a constant"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
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
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if is_comment_line(trimmed) {
            continue;
        }
        if let Some(needle) = NAN_NEEDLES.iter().find(|n| line.contains(*n)) {
            out.push(emit(path.clone(), line_idx + 1, line, needle));
        }
    }
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with('#')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, needle: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.cmp_to_nan",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "direct equality with NaN (`{}`) is always false",
            needle.trim()
        ),
        explanation: "By IEEE-754, `NaN` does not equal anything, including itself. \
             Comparing a value to `NaN` with `==` / `!=` / `===` / `!==` collapses \
             to a constant — the author almost certainly meant to test \
             whether the value IS NaN, which requires a dedicated predicate."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Use `Number.isNaN(x)` (JS/TS), `math.isnan(x)` (Python), \
             `x.is_nan()` (Rust), or `math.IsNaN(x)` (Go) instead of \
             direct equality."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
