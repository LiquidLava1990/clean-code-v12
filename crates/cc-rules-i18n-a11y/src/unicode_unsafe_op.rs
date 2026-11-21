//! `cc.i18n.unicode_unsafe_op` — byte-level / count-by-char ops on str.
//!
//! Heuristic: walk every [`NodeKind::Call`]; flag the call when its
//! callee text resolves to one of the canonical unsafe operations:
//!
//! - Python `len(s)` on a string-typed argument — counts code units in
//!   the underlying repr, not user-perceived characters.
//! - Rust `String::len`, `str::len`, `s.as_bytes()`, `s.chars().count()`
//!   — same hazard: byte / scalar count != grapheme count.
//! - Generic `bytes(s)` / `s.encode()` constructors.
//!
//! Phase-5 simplification: every callee match fires at `Severity::Nit`.
//! A future Phase will require taint flow from a UI-visible source
//! before firing.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{callee_text, nodes_of_kind};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, I18nA11yFindingBlueprint,
};

/// Family-15 probe R-I18N-UNICODE-UNSAFE-OP.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnicodeUnsafeOpRule;

const UNSAFE_OPS: &[&str] = &[
    "len(",
    ".as_bytes(",
    ".chars().count(",
    ".encode(",
    "bytes(",
    "String::len",
    "str::len",
];

impl Rule for UnicodeUnsafeOpRule {
    fn rule_id(&self) -> &'static str {
        "cc.i18n.unicode_unsafe_op"
    }
    fn category(&self) -> Category {
        Category::I18n
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "byte / code-unit count on a string masquerades as character count"
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
    let needle = UNSAFE_OPS.iter().find(|m| text.contains(*m))?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(I18nA11yFindingBlueprint {
        rule_id: "cc.i18n.unicode_unsafe_op",
        category: Category::I18n,
        severity: Severity::Nit,
        confidence: Confidence::new(0.5),
        location,
        headline: format!("`{needle}` counts bytes / code units, not graphemes"),
        explanation: format!(
            "`{needle}` reports the size of the underlying byte / code-unit \
             buffer. For UTF-8 / UTF-16 text the count diverges from \
             user-perceived characters whenever a code point is multi-byte \
             or a grapheme cluster spans multiple code points (emoji, \
             devanagari, combining marks). Truncating, padding, or \
             length-validating user input on this signal silently produces \
             mojibake."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Use a grapheme-aware iterator — `unicode-segmentation` in Rust, \
             `regex` with `\\X` in Python, `Intl.Segmenter` in JS, \
             `utf8.RuneCountInString` in Go for code points — when the \
             count is exposed to a user. Reserve byte / code-unit length \
             for buffer-allocation calculations."
                .into(),
        ),
        snippet: text,
        weight: 1,
    }))
}
