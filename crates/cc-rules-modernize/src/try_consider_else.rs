//! `cc.modernize.try_consider_else` — Python `try: x = call(); use(x)`
//! where the use can move into an `else:` block. Keeps the `try:` body
//! narrow to the operation that may raise, so `except` only catches
//! errors it actually meant to.
//!
//! Mirrors ruff `TRY300` (try-consider-else).
//!
//! Phase-9 detector: locate every [`NodeKind::Try`] node carrying a
//! `body_signature`/`signature` text. If the body looks like
//! `<lhs> = <call>` followed by additional non-raising statements
//! before the `except:`, suggest moving the trailing statements into
//! an `else:` branch.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.try_consider_else`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TryConsiderElseRule;

const TEXT_KEYS: &[&str] = &["body_signature", "body_text", "body", "signature"];

impl Rule for TryConsiderElseRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.try_consider_else"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Python `try:` body has trailing statements that belong in `else:`"
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
    if !looks_like_movable_tail(&body) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, node.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if path.extension() != Some("py") {
        return None;
    }
    let location = location_from_node(ctx.batch, node.id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.try_consider_else",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "`try:` body has trailing work that belongs in `else:`".into(),
        explanation: "Python's `try:` block should only contain the \
             operation that may raise. Trailing statements that can \
             only run when the call succeeded belong in `else:` — \
             that way `except:` cannot accidentally catch errors \
             raised by the success path. Today the body raises in \
             both spots and the handler swallows whichever fires."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Move the trailing statements into an `else:` block: \
             `try: x = call() except E: ... else: use(x)`. The \
             handler now sees only failures from `call()`."
                .into(),
        ),
        snippet: body,
        weight: 2,
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

/// Heuristic: the try body has a binding statement followed by a
/// non-`raise`/non-`return` statement before the `except:` keyword.
fn looks_like_movable_tail(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let Some(except_pos) = lower.find("except") else {
        return false;
    };
    let try_body = body[..except_pos].trim_end();
    let body_lines: Vec<&str> = try_body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && *line != "try:")
        .collect();
    if body_lines.len() < 2 {
        return false;
    }
    let head = body_lines[0];
    if !looks_like_binding(head) {
        return false;
    }
    body_lines
        .iter()
        .skip(1)
        .any(|line| !is_terminator(line) && !line.starts_with("try:"))
}

fn looks_like_binding(line: &str) -> bool {
    let Some(eq_pos) = line.find('=') else {
        return false;
    };
    if line.as_bytes().get(eq_pos + 1).copied() == Some(b'=') {
        return false;
    }
    let lhs = line[..eq_pos].trim();
    !lhs.is_empty()
        && lhs
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
}

fn is_terminator(line: &str) -> bool {
    line.starts_with("raise") || line.starts_with("return") || line == "raise" || line == "return"
}
