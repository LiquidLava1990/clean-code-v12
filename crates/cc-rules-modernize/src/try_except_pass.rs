//! `cc.modernize.try_except_pass` — `try: ... except SomeError: pass`
//! with no logging, comment, or compensating action. The exception is
//! silently swallowed and the operator never sees it.
//!
//! Mirrors ruff / bandit `S110` (try-except-pass).
//!
//! Phase-9 detector: locate every [`NodeKind::Try`] node carrying a
//! `body_signature`/`signature` text. If the body contains an
//! `except …: pass` block (allowing whitespace) with no preceding
//! `log`, `print`, `raise`, or `# noqa`/`# explanation` comment in the
//! same except clause, flag.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.try_except_pass`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TryExceptPassRule;

const TEXT_KEYS: &[&str] = &["body_signature", "body_text", "body", "signature"];

impl Rule for TryExceptPassRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.try_except_pass"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "`try: ... except E: pass` — silent catch with no log/comment"
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
    if !looks_like_silent_pass(&body) {
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
        rule_id: "cc.modernize.try_except_pass",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: "`except: pass` swallows errors silently".into(),
        explanation: "The except clause matches and then does nothing — \
             no log line, no comment explaining why this error class \
             is safe to drop, no compensating action. When this code \
             path fires in production the operator sees a feature \
             quietly stop working with no signal to debug from."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Pick one: log the exception (`logger.warning(\"…\", \
             exc_info=True)`), explain why the silent drop is safe \
             with a comment that names the specific scenario, or \
             re-raise after partial cleanup. If the catch is really \
             a no-op (it almost never is), the comment alone makes \
             that future-proof."
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

fn looks_like_silent_pass(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let Some(except_pos) = lower.find("except") else {
        return false;
    };
    let after_except = &body[except_pos..];
    // Require a `pass` statement somewhere after `except`.
    if !contains_bare_pass(after_except) {
        return false;
    }
    // Suppress when the except clause has any signal — log/print/raise
    // call OR an explanatory comment.
    if has_logging_or_signal(after_except) {
        return false;
    }
    if has_explanatory_comment(after_except) {
        return false;
    }
    true
}

fn contains_bare_pass(after_except: &str) -> bool {
    after_except
        .lines()
        .map(str::trim)
        .any(|line| line == "pass")
}

fn has_logging_or_signal(after_except: &str) -> bool {
    let lower = after_except.to_ascii_lowercase();
    lower.contains("log.")
        || lower.contains("logger.")
        || lower.contains("logging.")
        || lower.contains("print(")
        || lower.contains("raise ")
        || lower.contains("warnings.warn")
        || lower.contains("sys.stderr")
}

fn has_explanatory_comment(after_except: &str) -> bool {
    after_except
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with('#') && line.len() > 2)
}
