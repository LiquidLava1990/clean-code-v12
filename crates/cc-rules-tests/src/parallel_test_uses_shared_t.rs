//! `cc.test.parallel_test_uses_shared_t` — Go subtest closure captures
//! the outer `*testing.T` instead of the inner shadow.
//!
//! Pattern:
//!
//! ```text
//! func TestThing(t *testing.T) {
//!     for _, tc := range cases {
//!         tc := tc
//!         t.Run(tc.name, func(t *testing.T) {  // GOOD: shadow named `t`
//!             t.Parallel()
//!             tc.run(t)                         // uses inner `t`
//!         })
//!         //
//!         // BAD variant:
//!         t.Run(tc.name, func(subT *testing.T) {
//!             subT.Parallel()
//!             tc.run(t) // refers to OUTER t — race once parallel fires
//!         })
//!     }
//! }
//! ```
//!
//! Once `subT.Parallel()` is invoked, the outer `t` belongs to a
//! different test that may already be `Cleanup`-ing or `Fatal`-ing,
//! and using it from inside the subtest is a goroutine race + flaky
//! diagnostic mis-attribution.
//!
//! OSS source: golangci-lint `paralleltest` + `tparallel` rules.
//!
//! Phase-8 source-byte heuristic (`.go` only): scan for `t.Run(...,
//! func(<param> *testing.T) {`. If the parameter name is anything
//! other than `t` AND the body contains both `<param>.Parallel()` and
//! a bare token `t.` (the outer `t`), fire.
//!
//! Confidence 0.85 — false-positive risk: a benign closure that uses
//! `t.Helper()` only on the outer `t` is rare but possible.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, TestsFindingBlueprint};

/// Family-8 probe R-PARALLEL-TEST-SHARED-T.
#[derive(Debug, Default, Clone, Copy)]
pub struct ParallelTestUsesSharedTRule;

/// Lines of subtest body we scan for `Parallel()` + outer-`t` use.
const SUBTEST_BODY_WINDOW: usize = 60;

impl Rule for ParallelTestUsesSharedTRule {
    fn rule_id(&self) -> &'static str {
        "cc.test.parallel_test_uses_shared_t"
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
        "parallel subtest body uses the outer *testing.T instead of its shadow"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("go") {
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
        let Some(param) = parse_subtest_header(line) else {
            continue;
        };
        if param == "t" {
            continue;
        }
        if !subtest_calls_parallel(&lines, idx, param) {
            continue;
        }
        if !subtest_uses_outer_t(&lines, idx, param) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, line, param));
    }
}

/// Pull the parameter name out of `t.Run(..., func(<param> *testing.T) {`.
/// Returns `None` for any other shape.
fn parse_subtest_header(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let run_idx = trimmed.find("t.Run(")?;
    let after_run = &trimmed[run_idx + "t.Run(".len()..];
    let func_idx = after_run.find("func(")?;
    let after_func = &after_run[func_idx + "func(".len()..];
    let close = after_func.find(')')?;
    let signature = &after_func[..close];
    let param = signature.split_whitespace().next()?;
    if param.is_empty() {
        None
    } else {
        Some(param)
    }
}

fn subtest_calls_parallel(lines: &[&str], start_idx: usize, param: &str) -> bool {
    let needle = format!("{param}.Parallel()");
    let end = (start_idx + SUBTEST_BODY_WINDOW).min(lines.len());
    lines[start_idx..end].iter().any(|l| l.contains(&needle))
}

fn subtest_uses_outer_t(lines: &[&str], start_idx: usize, param: &str) -> bool {
    let end = (start_idx + SUBTEST_BODY_WINDOW).min(lines.len());
    for line in lines[start_idx + 1..end].iter() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if !line_uses_bare_t(line) {
            continue;
        }
        if !contains_outer_t(line, param) {
            continue;
        }
        return true;
    }
    false
}

/// True iff `line` contains a `t.` token that is NOT immediately
/// preceded by an identifier character (so `tc.` and `subT.` don't
/// match).
fn line_uses_bare_t(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut idx = 0;
    while let Some(found) = line[idx..].find("t.") {
        let absolute = idx + found;
        let prev = absolute.checked_sub(1).and_then(|i| bytes.get(i).copied());
        let bordered = prev.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !bordered {
            return true;
        }
        idx = absolute + 2;
    }
    false
}

/// True iff `line` carries an outer-`t.` token distinct from any
/// `<param>.` occurrence (we mask out param tokens before checking).
fn contains_outer_t(line: &str, param: &str) -> bool {
    let cleaned = line.replace(&format!("{param}."), "");
    line_uses_bare_t(&cleaned)
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, param: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(TestsFindingBlueprint {
        rule_id: "cc.test.parallel_test_uses_shared_t",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "parallel subtest closure parameter `{param}` shadowed but outer `t` is still used"
        ),
        explanation: format!(
            "The subtest body calls `{param}.Parallel()`, which detaches \
             execution from the outer test's goroutine. References to the \
             outer `t.` inside the same body race with the parent test's \
             cleanup / Fatal logic and produce flaky failure attribution. \
             Either rename the parameter to `t` (shadowing the outer one) \
             or replace every outer-`t.` use with `{param}.`."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Rename the closure parameter to `t` so the inner `*testing.T` \
             shadows the outer one, then delete the now-redundant variable. \
             If you genuinely need both, hoist the outer-`t` calls before \
             `t.Run` so they fire on the parent goroutine."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
