//! `cc.error.broad_catch` — flag overly broad-but-typed exception handlers.
//!
//! Citations: [ruff TRY002](https://docs.astral.sh/ruff/rules/raise-vanilla-class/),
//! [ruff BLE001 (blind-except)](https://docs.astral.sh/ruff/rules/blind-except/),
//! [pylint W0703](https://pylint.readthedocs.io/en/latest/user_guide/messages/warning/broad-except.html).
//!
//! What we flag:
//!
//! - Python: `except Exception:`, `except BaseException:`.
//! - Rust / Java: `catch Throwable`, `catch Error`, `catch Exception`.
//! - Go: `_ = recover()` is not a handler in this sense — out of scope.
//!
//! What we DO NOT flag:
//!
//! - Truly bare handlers (no type, `_`, `any`) — that is
//!   [`crate::error::bare::BareCatchRule`]'s territory, severity Blocker.
//! - Handlers that immediately re-raise — `raise`, `raise from`, `?`,
//!   `return Err(...)`, `throw e`. Re-raising preserves the stack and
//!   is the canonical "log + propagate" pattern.
//!
//! Severity is Blocker: granular-error discipline (the linter's S2/S5
//! design language) treats every public boundary catch as needing a
//! specific exception class plus a stable error code. Catching
//! `Exception` / `BaseException` / `Error` / `Throwable` defeats that
//! contract — every callsite that survives such a handler now has lost
//! provenance. Refactor on contact: name the specific failure mode you
//! handle, and let unexpected ones propagate.

use cc_cpg::{CpgWriteBatch, NodeId, NodeKind, Value};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{
    ast_parent, node_by_id, node_kind, nodes_of_kind, range_prop, string_prop,
};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, byte_window, enclosing_file_path, location_from_node, Tier0FindingBlueprint,
};

/// Catch-all type names that are "broad but typed" — every name here is
/// a concrete exception class, but it sits high enough in the hierarchy
/// that it absorbs unrelated failures.
const BROAD_TYPES: &[&str] = &["Exception", "BaseException", "Error", "Throwable"];

/// Substrings that, if present in the handler body, indicate the handler
/// re-raises rather than silently absorbing. A re-raise preserves the
/// original stack and is the canonical "log + propagate" pattern, so
/// matches here suppress the finding.
const RERAISE_NEEDLES: &[&str] = &[
    "raise\n",
    "raise ",
    "raise;",
    "raise#",
    "throw e",
    "throw err",
    "throw new",
    " ?;",
    " ?\n",
    " ?,",
    " ?)",
    "return Err(",
    "return err",
    ".context(",
];

/// Tier-0 forever rule R-ERR-BROAD-CATCH.
#[derive(Debug, Default, Clone, Copy)]
pub struct BroadCatchRule;

impl Rule for BroadCatchRule {
    fn rule_id(&self) -> &'static str {
        "cc.error.broad_catch"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.98)
    }
    fn description(&self) -> &'static str {
        "broad-but-typed exception handler (Exception / BaseException / Error / Throwable)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        nodes_of_kind(ctx.batch, NodeKind::Try)
            .filter_map(|node| build_broad_finding(ctx, node.id))
            .collect()
    }
}

fn build_broad_finding(ctx: &RuleContext<'_>, try_id: NodeId) -> Option<Finding> {
    // Two frontend shapes coexist:
    //   1. Java/Rust/TS: outer Try node carries `catches: NodeList` of
    //      handler nodes; each handler has `exception_type`.
    //   2. Python: each `except`-clause is its OWN Try node with
    //      `exception_type` set directly on it (no `catches` list).
    // We accept either: prefer the strict list when present, fall back
    // to inspecting the Try node itself.
    let path = enclosing_file_path(ctx.batch, try_id)?;
    let bytes = ctx.source.get(path.as_path());
    let broad_type = match collect_handlers_strict(ctx.batch, try_id) {
        Some(handlers) => handlers
            .iter()
            .find_map(|h| broad_handler_type(ctx, *h, bytes))?,
        // Fallback only fires when this Try is not nested inside an
        // outer Try's `catches` list — otherwise the outer would report
        // the same handler and we'd double-fire on every Python except.
        None if !is_inner_except_clause(ctx.batch, try_id) => {
            broad_handler_type(ctx, try_id, bytes)?
        }
        None => return None,
    };
    let location = location_from_node(ctx.batch, try_id, path);
    let snippet = string_prop(ctx.batch, try_id, "name")
        .unwrap_or("")
        .to_owned();
    Some(build_finding(Tier0FindingBlueprint {
        rule_id: "cc.error.broad_catch",
        category: Category::Bug,
        severity: Severity::Blocker,
        confidence: Confidence::new(0.98),
        location,
        headline: format!("broad exception type `{broad_type}` — narrow the catch or re-raise"),
        explanation: format!(
            "Handlers typed as `{broad_type}` swallow every subclass, including ones \
             unrelated to the operation in the try-block. Either narrow the type to \
             the specific exceptions the operation can raise, or re-raise after \
             logging so the original stack survives."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace with the specific exception(s) the call can actually raise \
             (e.g. `except (ValueError, KeyError):`), or keep the broad catch and \
             re-raise with `raise` / `?` / `return Err(...)` after logging."
                .into(),
        ),
        snippet,
        weight: 1,
    }))
}

/// Return the broad type name if `handler_id`'s `exception_type` is one
/// of [`BROAD_TYPES`] AND the handler body does not re-raise.
fn broad_handler_type(
    ctx: &RuleContext<'_>,
    handler_id: NodeId,
    bytes: &[u8],
) -> Option<&'static str> {
    let raw = string_prop(ctx.batch, handler_id, "exception_type")?;
    let trimmed = raw.trim();
    let matched: &'static str = *BROAD_TYPES.iter().find(|t| **t == trimmed)?;
    if handler_reraises(ctx.batch, handler_id, bytes) {
        return None;
    }
    Some(matched)
}

/// True iff the handler body contains a re-raise / propagate token.
/// Mirrors the substring approach used by `swallowed_with_log` so the
/// two rules agree on what counts as "propagated".
fn handler_reraises(batch: &CpgWriteBatch, handler_id: NodeId, bytes: &[u8]) -> bool {
    let Some(range) = range_prop(batch, handler_id, "range") else {
        return false;
    };
    let body = byte_window(bytes, range.start.offset, range.end.offset);
    let text = std::str::from_utf8(body).unwrap_or("");
    RERAISE_NEEDLES.iter().any(|needle| text.contains(needle))
}

fn collect_handlers_strict(batch: &CpgWriteBatch, try_id: NodeId) -> Option<Vec<NodeId>> {
    let node = node_by_id(batch, try_id)?;
    match node.prop("catches")? {
        Value::NodeList(ids) => Some(ids.clone()),
        _ => None,
    }
}

/// True when `try_id` is itself one of an enclosing Try node's per-except
/// clause children (the Python frontend shape). Detected by walking the
/// ast-parent chain to the nearest Try and checking whether that Try's
/// `catches` list contains us.
fn is_inner_except_clause(batch: &CpgWriteBatch, try_id: NodeId) -> bool {
    let mut current = try_id;
    for _ in 0..16_u8 {
        let Some(parent) = ast_parent(batch, current) else {
            return false;
        };
        if node_kind(batch, parent) == Some(NodeKind::Try) {
            return collect_handlers_strict(batch, parent)
                .is_some_and(|catches| catches.contains(&try_id));
        }
        current = parent;
    }
    false
}
