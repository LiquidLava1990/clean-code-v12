//! `cc.bug.locale_dependent` — locale-dependent case operations.
//!
//! Heuristic: flag every [`NodeKind::Call`] whose callee text resolves to
//! one of the canonical case-changing methods:
//!
//! - Python `str.upper`, `str.lower`, `str.title`, `str.casefold`.
//! - Rust `String::to_uppercase`, `String::to_lowercase`,
//!   `str::to_ascii_uppercase`, `str::to_ascii_lowercase`.
//! - Go `strings.ToUpper`, `strings.ToLower`, `strings.Title`.
//! - JS / TS `String.prototype.toUpperCase`, `toLowerCase`,
//!   `toLocaleUpperCase`, `toLocaleLowerCase`.
//!
//! Phase-3 simplification: every hit is flagged at `Severity::Nit` so
//! adoption is gradual. Phase-4 will narrow to "user input flows in"
//! once taint propagation lands.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    BugFindingBlueprint,
};

/// Family-3 probe R-LOCALE-DEPENDENT.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocaleDependentRule;

const LOCALE_METHODS: &[&str] = &[
    ".upper(",
    ".lower(",
    ".title(",
    ".casefold(",
    "to_uppercase",
    "to_lowercase",
    "to_ascii_uppercase",
    "to_ascii_lowercase",
    "strings.ToUpper",
    "strings.ToLower",
    "strings.Title",
    "toUpperCase",
    "toLowerCase",
    "toLocaleUpperCase",
    "toLocaleLowerCase",
];

impl Rule for LocaleDependentRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.locale_dependent"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "locale-dependent case operation without explicit locale"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let text = callee_text(ctx.batch, id);
    let needle = LOCALE_METHODS.iter().find(|m| text.contains(*m))?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.locale_dependent",
        severity: Severity::Nit,
        confidence: Confidence::new(0.5),
        location,
        headline: format!("`{needle}` is locale-sensitive — Turkish-i + ß bite here"),
        explanation: format!(
            "`{needle}` performs case mapping that varies by locale. The \
             classic Turkish-i bug (`'I'.lower()` returns `ı` not `i` under \
             tr_TR) and the German `ß → SS` round-trip are real production \
             defects from this family. When comparing user input, prefer a \
             locale-stable form."
        ),
        remediation: Remediation::SuggestedRewrite(
            "For comparisons use `casefold()` (Python), `to_ascii_lowercase` \
             (Rust, when the input is ASCII), `strings.EqualFold` (Go), or \
             a `toLocaleLowerCase('en-US')` with an explicit locale (JS). \
             For display, set the locale explicitly."
                .into(),
        ),
        snippet: text,
        weight: 1,
    }))
}
