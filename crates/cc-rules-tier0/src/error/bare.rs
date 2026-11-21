//! `cc.error.bare` — flag bare `except` / bare `raise` / `catch (_)`.
//!
//! NOTE: This rule itself MUST NOT contain a bare `except` or `catch` —
//! see the dogfood test in `crate::tests`. We use typed catches and
//! match on a closed enum throughout.

use cc_cpg::{NodeId, NodeKind, Value};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{node_by_id, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

/// Tier-0 forever rule R-ERR-BARE.
#[derive(Debug, Default, Clone, Copy)]
pub struct BareCatchRule;

impl Rule for BareCatchRule {
    fn rule_id(&self) -> &'static str {
        "cc.error.bare"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "bare `except` / `raise` / `catch` swallows error context"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        nodes_of_kind(ctx.batch, NodeKind::Try)
            .filter(|node| try_has_bare_handler(ctx, node.id))
            .filter_map(|node| build_bare_finding(ctx, node.id))
            .collect()
    }
}

fn build_bare_finding(ctx: &RuleContext<'_>, try_id: NodeId) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, try_id)?;
    let location = location_from_node(ctx.batch, try_id, path);
    let snippet = string_prop(ctx.batch, try_id, "name")
        .unwrap_or("")
        .to_owned();
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.error.bare",
        category: Category::Bug,
        severity: Severity::Blocker,
        confidence: Confidence::certain(),
        location,
        headline: "bare exception handler — no specific error type".into(),
        explanation:
            "Bare handlers swallow every error, including KeyboardInterrupt and SystemExit. \
         Tier-0 requires a specific exception type or a re-raise with context."
                .into(),
        remediation: Remediation::SuggestedRewrite(
            "Catch a specific exception (e.g. `except ValueError as exc:`) and either \
             handle the failure or re-raise with `raise ... from exc`."
                .into(),
        ),
        snippet,
        weight: 2,
    }))
}

/// True when at least one of the Try's handlers is bare (no exception type).
///
/// Only Try nodes that explicitly carry a `catches` NodeList are
/// inspected. Frontends that build per-except-clause Try nodes (Python's
/// `lift_try` does this) emit those inner Trys as siblings of the outer
/// Try with `catches`; iterating both would double-count handlers and
/// misclassify the inner Try (whose AST_PARENT children are body
/// `Block`s without an `exception_type` prop) as bare every time.
fn try_has_bare_handler(ctx: &RuleContext<'_>, try_id: NodeId) -> bool {
    let Some(handlers) = handler_list(ctx, try_id) else {
        return false;
    };
    handlers.iter().any(|h| handler_is_bare(ctx, *h))
}

fn handler_list(ctx: &RuleContext<'_>, try_id: NodeId) -> Option<Vec<NodeId>> {
    match node_by_id(ctx.batch, try_id)?.prop("catches")? {
        Value::NodeList(ids) => Some(ids.clone()),
        _ => None,
    }
}

/// A handler is "bare" when:
/// - it has no `exception_type` property, OR
/// - the property is the empty string (frontend's "no type" marker), OR
/// - the property is a language-level catch-all wildcard (`_` in Rust,
///   `any` in TypeScript).
///
/// `Exception`, `BaseException`, `Error`, and `Throwable` are NOT bare —
/// they are typed (broad, but typed) and belong to
/// [`crate::error::broad_catch`] which carries Required severity. Only
/// truly bare handlers (`except:`) live here.
fn handler_is_bare(ctx: &RuleContext<'_>, handler_id: NodeId) -> bool {
    let exception_type = string_prop(ctx.batch, handler_id, "exception_type");
    match exception_type {
        Some(t) => is_bare_alias(t),
        None => true,
    }
}

fn is_bare_alias(t: &str) -> bool {
    let trimmed = t.trim();
    trimmed.is_empty() || matches!(trimmed, "any" | "_")
}
