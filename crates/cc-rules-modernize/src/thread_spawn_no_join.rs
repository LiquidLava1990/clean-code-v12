//! `cc.modernize.thread_spawn_no_join` — Rust `std::thread::spawn` whose
//! `JoinHandle` is dropped without `.join()`.
//!
//! Pairs with `cc.concurrent.leaked_task` but is Rust-specific and
//! Phase-6 conservative: we flag any [`NodeKind::Call`] whose callee
//! text contains `thread::spawn` AND whose AST parent is *not* a
//! [`NodeKind::Write`] (no binding) and not a [`NodeKind::Return`]
//! (handle returned to caller).
//!
//! Severity: `Required` — leaked threads keep their stack alive past
//! the parent function and silently swallow panics.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, ModernizeFindingBlueprint,
};

/// Family-26 probe `cc.modernize.thread_spawn_no_join`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadSpawnNoJoinRule;

impl Rule for ThreadSpawnNoJoinRule {
    fn rule_id(&self) -> &'static str {
        "cc.modernize.thread_spawn_no_join"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "Rust `thread::spawn` whose JoinHandle is dropped"
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
    if !looks_like_thread_spawn(&text) {
        return None;
    }
    if handle_is_captured(ctx, id) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    if !path.as_str().ends_with(".rs") {
        return None;
    }
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(ModernizeFindingBlueprint {
        rule_id: "cc.modernize.thread_spawn_no_join",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: "`thread::spawn` handle dropped — thread leaks on panic".into(),
        explanation: "`std::thread::spawn` returns a `JoinHandle<T>`. When \
             that handle is dropped without `.join()`, panics inside the \
             thread vanish and the parent has no way to observe completion. \
             For background work prefer a tracked task pool; for one-shot \
             threads always bind the handle and `.join()` it before exit."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Bind the handle (`let handle = thread::spawn(...)`) and \
             `.join()` it before the parent scope exits, or migrate to a \
             scoped-thread API (`std::thread::scope`) that joins on drop."
                .into(),
        ),
        snippet: text,
        weight: 2,
    }))
}

fn looks_like_thread_spawn(text: &str) -> bool {
    text.contains("thread::spawn") || text.contains("std::thread::spawn")
}

fn handle_is_captured(ctx: &RuleContext<'_>, id: NodeId) -> bool {
    let Some(parent) = ast_parent(ctx.batch, id) else {
        return false;
    };
    let parent_kind = node_kind(ctx.batch, parent);
    matches!(
        parent_kind,
        Some(NodeKind::Write) | Some(NodeKind::Variable) | Some(NodeKind::Return)
    )
}
