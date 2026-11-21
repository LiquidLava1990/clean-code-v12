//! `cc.bug.broad_pytest_raises` — `pytest.raises(Exception):` instead of
//! a specific subclass. Catches every error type, hiding latent bugs
//! the test was never written to assert against.
//!
//! Mirrors ruff `B017` (assert-raises-exception).
//!
//! Phase-9 detector: scan every Python file once for `pytest.raises(<X>)`
//! / `with raises(<X>):` invocations whose argument is a top-level
//! broad type — `Exception`, `BaseException`. Confidence 0.85; some
//! tests legitimately want the broad surface for boundary checks.
//!
//! Note: this probe deliberately fires on test files — it is the
//! whole point. Other Phase-9 probes skip tests via `is_test_file_path`.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, looks_like_rule_pack_source, BugFindingBlueprint};

/// Family-3 probe `cc.bug.broad_pytest_raises`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BroadPytestRaisesRule;

/// Exception types broad enough to mask real bugs.
const BROAD_EXCEPTIONS: &[&str] = &["Exception", "BaseException"];

impl Rule for BroadPytestRaisesRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.broad_pytest_raises"
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
        "`pytest.raises(Exception)` — too broad, masks unrelated failures"
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
            if looks_like_rule_pack_source(&path) {
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
        if let Some(broad) = find_broad_raises(line) {
            out.push(emit(path.clone(), line_idx + 1, line, broad));
        }
    }
}

/// Return the first broad exception name used as the first positional
/// argument to `pytest.raises(...)` / `raises(...)` on this line.
fn find_broad_raises(line: &str) -> Option<&'static str> {
    for needle in ["pytest.raises(", "raises("] {
        if let Some(broad) = scan_needle(line, needle) {
            return Some(broad);
        }
    }
    None
}

fn scan_needle(line: &str, needle: &str) -> Option<&'static str> {
    let mut start = 0usize;
    while let Some(found) = line[start..].find(needle) {
        let abs = start + found;
        if needle == "raises(" && has_token_prefix(line, abs) {
            start = abs + needle.len();
            continue;
        }
        let after = &line[abs + needle.len()..];
        if let Some(broad) = first_arg_is_broad(after) {
            return Some(broad);
        }
        start = abs + needle.len();
    }
    None
}

fn has_token_prefix(line: &str, abs: usize) -> bool {
    if abs == 0 {
        return false;
    }
    let prev = line.as_bytes()[abs - 1];
    prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'.'
}

fn first_arg_is_broad(after_open: &str) -> Option<&'static str> {
    let trimmed = after_open.trim_start();
    for broad in BROAD_EXCEPTIONS {
        if trimmed.starts_with(broad) {
            let next = trimmed.as_bytes().get(broad.len()).copied();
            let ok = matches!(
                next,
                None | Some(b',') | Some(b')') | Some(b' ') | Some(b'\t')
            );
            if ok {
                return Some(broad);
            }
        }
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, broad: &str) -> Finding {
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
        rule_id: "cc.bug.broad_pytest_raises",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`pytest.raises({broad})` is too broad"),
        explanation: format!(
            "`pytest.raises({broad})` catches every error, including \
             `AttributeError` from a missing import, `ImportError` from \
             a typo, `KeyboardInterrupt`, and any unrelated bug the \
             code under test happens to hit. The test passes for the \
             wrong reason and the failure mode you wanted to assert \
             goes unverified."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Use the most specific exception type the code raises. \
             Pair `match=` to pin the message: \
             `pytest.raises(ValueError, match=r\"out of range\")`. If \
             you genuinely want the broad surface (e.g. a custom \
             exception hierarchy under `Exception`), document why with \
             a comment so future readers know it was deliberate."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
