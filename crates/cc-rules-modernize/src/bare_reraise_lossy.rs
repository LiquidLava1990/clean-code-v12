//! `cc.modernize.bare_reraise_lossy` — Python `except E as e: raise
//! Other(...)` without `from e` / `from None` loses the original
//! traceback chain.
//!
//! Mirrors ruff `B904` and pyflakes' broader `raise-from` family.
//! Detection: any [`NodeKind::Try`] node carrying a `body_signature`
//! / `signature` that contains an `except …:` block followed by a
//! `raise ` whose tail is missing both `from e` and `from None`.
//!
//! Severity: `Nit` — the wrapped `Other` exception still propagates;
//! the lost data is the `__cause__` chain. Many projects still write
//! this pattern by reflex.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.bare_reraise_lossy`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BareReraiseLossyRule;

const TEXT_KEYS: &[&str] = &["body_signature", "body_text", "body", "signature"];

impl Rule for BareReraiseLossyRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.bare_reraise_lossy"
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
        "Python `raise X` inside `except` without `from e`/`from None`"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Try) {
            if let Some(finding) = check_try(ctx, node) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_try(ctx: &RuleContext<'_>, node: &Node) -> Option<Finding> {
    let body = try_body_text(ctx, node.id)?;
    if !looks_like_lossy_reraise(&body) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, node.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if !path.as_str().ends_with(".py") {
        return None;
    }
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.bare_reraise_lossy",
        severity: Severity::Nit,
        confidence: Confidence::new(0.9),
        location,
        headline: "`raise X` inside `except` drops the cause chain".into(),
        explanation: "`raise NewError(...)` inside an `except` block sets \
             the new exception's `__context__` to the original (so the \
             traceback shows both), but `__cause__` stays `None`. Tools \
             that look at the cause chain treat the original as \
             accidental rather than the explicit reason for the new \
             exception. `raise NewError(...) from e` records the link, \
             and `raise NewError(...) from None` deliberately suppresses \
             the original."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Suffix the `raise` with `from e` to chain the original cause, \
             or `from None` to deliberately drop it. Bare `raise` (re-raise \
             the same exception) is also fine when no transformation is \
             needed."
                .into(),
        ),
        snippet: body,
        weight: 1,
    }))
}

fn try_body_text(ctx: &RuleContext<'_>, id: NodeId) -> Option<String> {
    for key in TEXT_KEYS {
        if let Some(value) = string_prop(ctx.batch, id, key) {
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn looks_like_lossy_reraise(body: &str) -> bool {
    if !body.contains("except") {
        return false;
    }
    let normalized = collapse_whitespace(body);
    let lower = normalized.to_ascii_lowercase();
    let raise_pos = lower.find("raise ");
    let Some(start) = raise_pos else {
        return false;
    };
    if !lower[..start].contains("except") {
        return false;
    }
    let tail = &lower[start..];
    if tail.contains(" from ") {
        // `from e` / `from None` / `from exc` already present.
        return false;
    }
    // Only flag when the raise is constructing a NEW exception —
    // `raise SomeError(` — bare `raise` (no args) is the canonical
    // re-raise and stays silent.
    tail.contains("raise ") && tail.contains('(')
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}
