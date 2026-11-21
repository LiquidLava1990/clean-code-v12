//! `cc.test.pt_fixture_returns_value` — pytest fixture that returns a
//! non-trivial value but is decorated as a bare `@pytest.fixture`
//! (without an explicit `scope=`) AND whose name does not start with
//! `_` (private convention).
//!
//! Mirrors ruff PT004 / PT022 family. The motivation: a fixture that
//! returns a value is a value-producer; without a documented scope the
//! reader can't tell whether the value is recreated per-test or shared,
//! and an exported public name implies "intended for callers". The
//! combination of the three signals (returns value + bare decorator +
//! public name) is the highest-confidence shape for the lint.
//!
//! Phase-10 source-byte detector: `.py` files only, scan every line for
//! `@pytest.fixture` (no parens, or empty parens). For each, find the
//! immediately following `def NAME(...)` whose name does not start with
//! `_`, then look ahead in the function body for a non-trivial
//! `return X` statement (X is not `None` / empty).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TestDesignFindingBlueprint,
};

/// Family-28 probe `cc.test.pt_fixture_returns_value`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PtFixtureReturnsValueRule;

/// Cap on the number of body lines we inspect for a `return` statement.
/// Pytest fixtures rarely span more than a couple of dozen lines.
const FIXTURE_BODY_LOOKAHEAD: usize = 80;

impl Rule for PtFixtureReturnsValueRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.pt_fixture_returns_value"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Test
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "pytest fixture returns a value but uses bare `@pytest.fixture` (no explicit scope)"
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
            if !is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
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
    for idx in 0..lines.len() {
        if !is_bare_fixture_decorator(lines[idx]) {
            continue;
        }
        let Some(def_idx) = find_def_after(&lines, idx) else {
            continue;
        };
        let Some(name) = parse_def_name(lines[def_idx]) else {
            continue;
        };
        if name.starts_with('_') {
            continue;
        }
        if !body_returns_non_trivial(&lines, def_idx) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, lines[idx], &name));
    }
}

/// True iff `line` is a bare `@pytest.fixture` (or `@pytest.fixture()`).
fn is_bare_fixture_decorator(line: &str) -> bool {
    let trimmed = line.trim_start();
    let stripped = trimmed.trim_end();
    stripped == "@pytest.fixture"
        || stripped == "@pytest.fixture()"
        || stripped == "@fixture"
        || stripped == "@fixture()"
}

/// Walk forward from `start` skipping decorators / blank lines and
/// return the index of the next `def NAME(...):` line.
fn find_def_after(lines: &[&str], start: usize) -> Option<usize> {
    let cap = (start + 1 + 4).min(lines.len());
    for idx in (start + 1)..cap {
        let trimmed = lines[idx].trim_start();
        if trimmed.is_empty() || trimmed.starts_with('@') || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("def ") {
            return Some(idx);
        }
        return None;
    }
    None
}

fn parse_def_name(line: &str) -> Option<String> {
    let after = line.trim_start().strip_prefix("def ")?.trim_start();
    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Walk forward from the def line. Stop at the first `return X` and
/// inspect the value. Bounded scan for a deeply-indented return.
fn body_returns_non_trivial(lines: &[&str], def_idx: usize) -> bool {
    let cap = (def_idx + 1 + FIXTURE_BODY_LOOKAHEAD).min(lines.len());
    for idx in (def_idx + 1)..cap {
        let trimmed = lines[idx].trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let unindented = lines[idx].len() == trimmed.len();
        if unindented {
            // Body ended (next top-level def / class / decorator).
            return false;
        }
        if let Some(rest) = trimmed.strip_prefix("return") {
            let after = rest.trim();
            return !after.is_empty() && after != "None";
        }
        if trimmed.starts_with("yield") {
            // `yield` style fixtures are out-of-scope; PT022 covers them.
            return false;
        }
    }
    false
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, fixture_name: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: Some(fixture_name.to_owned()),
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(TestDesignFindingBlueprint {
        rule_id: "cc.test.pt_fixture_returns_value",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("fixture `{fixture_name}` returns a value with bare `@pytest.fixture`"),
        explanation: format!(
            "`{fixture_name}` is decorated as a plain `@pytest.fixture` \
             but its body returns a value and the name is public (does \
             not start with `_`). The reader cannot tell whether the \
             produced value is shared or recreated per-test, and the \
             public name signals it is intended for direct use. Make \
             the scope explicit, or rename to `_{fixture_name}` if the \
             fixture is truly an internal helper."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add an explicit scope: `@pytest.fixture(scope=\"function\")` \
             (or `\"module\"` / `\"session\"` if the value is expensive \
             and reusable). If the fixture is internal, prefix the name \
             with `_` to mark it private."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
