//! `cc.bug.mutable_arg_default` — Python `def f(x=[])` / `def f(x={})`
//! / `def f(x=set())`. Mutable default arguments are evaluated once at
//! function-definition time and shared across every call — a classic
//! source of "ghost state" bugs.
//!
//! Mirrors ruff `B006` (mutable-argument-default).
//!
//! Phase-9 detector: scan every Python file once for `def NAME(` lines
//! containing a parameter with a mutable default. Source-byte heuristic
//! avoids the need for AST parameter nodes which the frontend does not
//! yet expose at the per-default granularity.
//!
//! Confidence 0.95 — the pattern is unambiguous when matched.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.mutable_arg_default`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MutableArgDefaultRule;

/// Mutable default expressions ruff B006 flags. Each entry is a
/// substring matched after the `=` of a default value.
const MUTABLE_DEFAULTS: &[&str] = &["[]", "{}", "set()", "list()", "dict()", "[ ]", "{ }"];

impl Rule for MutableArgDefaultRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.mutable_arg_default"
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
        "Python function parameter with a mutable default value"
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
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("def ") && !trimmed.starts_with("async def ") {
            continue;
        }
        if let Some(default) = find_mutable_default(line) {
            out.push(emit(path.clone(), line_idx + 1, line, default));
        }
    }
}

/// Locate the first `=<mutable>` segment inside the parameter list of
/// the `def …(…)` header. Walks paren depth so default expressions
/// containing nested calls do not break the scan.
fn find_mutable_default(line: &str) -> Option<&'static str> {
    let bytes = line.as_bytes();
    let open = line.find('(')?;
    let mut depth: i32 = 1;
    let mut idx = open + 1;
    while idx < bytes.len() && depth > 0 {
        match bytes[idx] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 1 && bytes.get(idx + 1).copied() != Some(b'=') => {
                let after = line[idx + 1..].trim_start();
                if let Some(hit) = match_mutable_default(after) {
                    return Some(hit);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

fn match_mutable_default(after_eq: &str) -> Option<&'static str> {
    for candidate in MUTABLE_DEFAULTS {
        if after_eq.starts_with(candidate) {
            return Some(candidate);
        }
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, default: &str) -> Finding {
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
        rule_id: "cc.bug.mutable_arg_default",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("mutable default `{default}` shared across calls"),
        explanation: format!(
            "Parameter defaults like `{default}` are evaluated once when \
             the function is defined, not on every call. The same object \
             is reused, so mutations from one call leak into every \
             subsequent call that relies on the default. The bug is \
             usually invisible until the function is called twice."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Default the parameter to `None` and build the mutable value \
             inside the body: `def f(x: list[int] | None = None): x = \
             [] if x is None else x`. The new instance per call is always \
             what callers expect."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
