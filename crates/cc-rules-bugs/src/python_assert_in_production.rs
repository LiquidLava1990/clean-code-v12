//! `cc.bug.python_assert_in_production` — Python `assert ...` statement
//! in non-test code.
//!
//! Canonical bug:
//! ```python
//! def authorize(user):
//!     assert user.is_admin, "must be admin"   # disappears under -O
//!     do_privileged_thing()
//! ```
//! CPython's `-O` (optimise) flag strips every `assert` statement at
//! parse time. Anything that relied on the assertion to enforce a
//! runtime invariant — argument validation, security check, state
//! gate — silently disappears in production builds. Bandit B101
//! flags this for exactly this reason.
//!
//! OSS source: Bandit `B101` (`assert_used`).
//!
//! Phase-12 source-byte heuristic: `.py` files only. Skip test files
//! (`tests/`, `test_*.py`, `*_test.py`, conftest.py — pytest expects
//! `assert` and rewrites it). Skip rule-pack source. Find any line
//! whose first token is `assert` (allowing leading indent).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.python_assert_in_production`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PythonAssertInProductionRule;

impl Rule for PythonAssertInProductionRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.python_assert_in_production"
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
        "Python `assert` in production code — stripped under `-O`"
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
            if is_conftest(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn is_conftest(path: &Utf8PathBuf) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_ascii_lowercase() == "conftest.py")
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
        if line_is_production_assert(line) {
            out.push(emit(path.clone(), idx + 1, line));
        }
    }
}

/// True iff `line` starts with the `assert` keyword (allowing indent).
/// Excludes the import statement `import assert` (rare typo) and string
/// literals like `"assert ..."` by requiring the keyword to be the
/// first non-whitespace token followed by a space, paren, or EOL.
fn line_is_production_assert(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("#") {
        return false;
    }
    let rest = match trimmed.strip_prefix("assert") {
        Some(r) => r,
        None => return false,
    };
    match rest.chars().next() {
        Some(c) if c == ' ' || c == '(' || c == '\t' => true,
        None => false, // bare `assert` with no expression — invalid Python anyway
        _ => false,
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.python_assert_in_production",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "`assert` in production code — stripped under `python -O`".into(),
        explanation: "CPython's `-O` flag (and `-OO`, and `PYTHONOPTIMIZE=1`) \
             removes every `assert` statement at parse time. Any check \
             that relied on the assertion — argument validation, \
             security gate, invariant enforcement — silently \
             disappears in optimised production builds. The function \
             then runs with whatever invalid input slipped past, and \
             the bug surfaces somewhere downstream miles from the \
             cause. Bandit `B101` flags this exact pattern."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace runtime checks with explicit error raising: \
             `if not condition: raise ValueError(\"...\")`. Reserve \
             `assert` for: (1) test code (pytest rewrites them with \
             rich diff output), (2) self-tests on internal invariants \
             that you accept losing under `-O`. If the assertion \
             enforces a security boundary, ALWAYS use an explicit \
             `raise` instead."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
