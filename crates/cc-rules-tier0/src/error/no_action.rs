//! `cc.error.no_action` — flag error-construction sites whose message
//! lacks a remediation hint.
//!
//! Heuristic (no LLM in Phase 1): scan every `Call` whose `name` is one
//! of `raise` / `throw` / `panic!` / `errors.New` / `fmt.Errorf`. Read
//! the literal message from the call's `message` property (frontend
//! lowers the first string-literal argument). Flag if the message:
//!
//! - is shorter than 80 characters,
//! - contains no newline, AND
//! - does not contain any of the verbs `try`, `use`, `set`, `add`,
//!   `remove`, `check` (case-insensitive).
//!
//! TODO(W3): replace heuristic with the LLM probe in `R-ERR-ACTION`'s
//! full spec once the LLM cache is wired.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

const MAX_NON_ACTIONABLE_LEN: usize = 80;
const ACTION_VERBS: &[&str] = &["try ", "use ", "set ", "add ", "remove ", "check "];

/// Tier-0 forever rule R-ERR-ACTION.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoActionRule;

impl Rule for NoActionRule {
    fn rule_id(&self) -> &'static str {
        "cc.error.no_action"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "raise/throw site has no actionable remediation in the message"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        for node in nodes_of_kind(ctx.batch, NodeKind::Return) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let callee = string_prop(ctx.batch, id, "name").unwrap_or("");
    if !is_error_constructor(callee) {
        return None;
    }
    let message = string_prop(ctx.batch, id, "message")?;
    if !is_non_actionable(message) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.error.no_action",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("`{callee}` message lacks a remediation hint"),
        explanation: format!(
            "Error messages must tell the user what to do. The `{callee}` site \
             ships a short message with no action verb (try/use/set/add/remove/check). \
             Readers cannot recover without one."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Rewrite the message in two halves: WHAT happened + HOW to fix \
             (verb + concrete next step, e.g. \"set ANTHROPIC_API_KEY env var\")."
                .into(),
        ),
        snippet: message.to_owned(),
        weight: 1,
    }))
}

fn is_error_constructor(name: &str) -> bool {
    matches!(
        name,
        "raise" | "throw" | "panic!" | "panic" | "errors.New" | "fmt.Errorf"
    )
}

fn is_non_actionable(message: &str) -> bool {
    if message.contains('\n') {
        return false;
    }
    if message.len() >= MAX_NON_ACTIONABLE_LEN {
        return false;
    }
    let lower = message.to_ascii_lowercase();
    !ACTION_VERBS.iter().any(|verb| lower.contains(verb))
}
