//! `cc.bug.lock_held_across_await` — `MutexGuard` (or any `.lock()` /
//! `.lock().unwrap()` binding) held across an `.await` point in an
//! async block.
//!
//! Syntactic shadow of `clippy::await_holding_lock`; full version
//! requires lifetime-aware data-flow. We approximate by reading the
//! source bytes inside each async function and matching:
//!
//! - The body contains both a `.lock()` call (or `.lock().unwrap()`,
//!   `.read()`, `.write()`) AND a subsequent `.await`.
//! - The lock binding is not consumed before the `.await` (no `drop(`
//!   or `}` closing the binding's scope between the lock and the
//!   await).
//!
//! Restricted to `rust` / `rs`. The body bytes come from the
//! frontend's per-file source mirror so this probe degrades to silence
//! when bytes are absent.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{bool_prop, nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, byte_slice_str, enclosing_file_language, enclosing_file_path, file_source_text,
    is_test_file_path, location_from_node, looks_like_rule_pack_source, TypesFindingBlueprint,
};

/// Family-22 probe R-BUG-LOCK-HELD-ACROSS-AWAIT.
#[derive(Debug, Default, Clone, Copy)]
pub struct LockHeldAcrossAwaitRule;

const LOCK_NEEDLES: &[&str] = &[".lock()", ".read()", ".write()"];

impl Rule for LockHeldAcrossAwaitRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.lock_held_across_await"
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
        "MutexGuard / RwLockGuard held across `.await` in an async block"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(finding) = check_async_function(ctx, node.id) {
                    out.push(finding);
                }
            }
        }
        out
    }
}

fn check_async_function(ctx: &RuleContext<'_>, fn_id: NodeId) -> Option<Finding> {
    let language = enclosing_file_language(ctx.batch, fn_id)?;
    if !is_rust(&language) {
        return None;
    }
    if !is_async_function(ctx, fn_id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, fn_id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let body = function_body(ctx, fn_id, &path)?;
    let lock_marker = find_lock_marker(&body)?;
    if !holds_lock_across_await(&body, lock_marker) {
        return None;
    }
    let name = string_prop(ctx.batch, fn_id, "name").unwrap_or("<anonymous>");
    let location = location_from_node(ctx.batch, fn_id, path);
    Some(build_finding(TypesFindingBlueprint {
        rule_id: "cc.bug.lock_held_across_await",
        category: Category::Bug,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("async fn `{name}` holds `{lock_marker}` guard across `.await`"),
        explanation: format!(
            "`{name}` acquires `{lock_marker}` and then awaits a future \
             without dropping the guard. The executor may park the task and \
             schedule another task that needs the same lock — instant \
             deadlock under tokio multi-thread runtime."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Scope the guard with a block: `let value = { let g = m.lock(); \
             g.value.clone() }; do_async(value).await;` or switch to an \
             async-aware lock (`tokio::sync::Mutex::lock().await`)."
                .into(),
        ),
        snippet: lock_marker.to_owned(),
        weight: 5,
    }))
}

fn is_rust(language: &str) -> bool {
    matches!(language.to_ascii_lowercase().as_str(), "rust" | "rs")
}

fn is_async_function(ctx: &RuleContext<'_>, fn_id: NodeId) -> bool {
    if bool_prop(ctx.batch, fn_id, "is_async").unwrap_or(false) {
        return true;
    }
    let signature = string_prop(ctx.batch, fn_id, "signature").unwrap_or("");
    signature.contains("async fn") || signature.starts_with("async ")
}

fn function_body(
    ctx: &RuleContext<'_>,
    fn_id: NodeId,
    path: &camino::Utf8PathBuf,
) -> Option<String> {
    let range = range_prop(ctx.batch, fn_id, "range")?;
    let bytes = file_source_text(ctx, path)?;
    byte_slice_str(bytes, range.start.offset, range.end.offset).map(str::to_owned)
}

fn find_lock_marker(body: &str) -> Option<&'static str> {
    LOCK_NEEDLES
        .iter()
        .copied()
        .find(|needle| body.contains(needle))
}

fn holds_lock_across_await(body: &str, lock_marker: &str) -> bool {
    let Some(lock_idx) = body.find(lock_marker) else {
        return false;
    };
    let after_lock = &body[lock_idx + lock_marker.len()..];
    let Some(await_idx) = after_lock.find(".await") else {
        return false;
    };
    let between = &after_lock[..await_idx];
    !between.contains("drop(") && !between.contains("}\n") && !between.contains("};")
}
