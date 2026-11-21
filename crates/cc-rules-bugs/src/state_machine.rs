//! `cc.bug.state_machine` — close-then-read on a single binding.
//!
//! Heuristic: enumerate [`NodeKind::Write`] nodes whose `initializer`
//! looks like a resource-opening call (`open(`, `connect(`, `acquire(`,
//! `File::open`). For each such write we collect every subsequent
//! [`NodeKind::Call`] in the same [`NodeKind::File`] whose `receiver`
//! property equals the write's `target`. The earliest call whose method
//! name is `close` / `disconnect` / `release` is the boundary; if any
//! later call uses the same receiver, the rule fires.
//!
//! Frontends that don't surface `receiver` keep this probe silent rather
//! than emitting false positives.

use cc_cpg::{Node, NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{node_by_id, nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, is_test_file_path, location_from_node, BugFindingBlueprint,
};

/// Family-3 probe R-STATE-MACHINE.
#[derive(Debug, Default, Clone, Copy)]
pub struct StateMachineRule;

const OPEN_PRODUCERS: &[&str] = &[
    "open(",
    "connect(",
    "acquire(",
    "File::open",
    "TcpStream::connect",
    ".connect(",
    "lock(",
];

const CLOSE_METHODS: &[&str] = &["close", "disconnect", "release", "shutdown", "drop"];

impl Rule for StateMachineRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.state_machine"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "method called on a resource after close()/disconnect()/release()"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Write) {
            let Some(finding) = check_write(ctx, node) else {
                continue;
            };
            out.push(finding);
        }
        out
    }
}

fn check_write(ctx: &RuleContext<'_>, write: &Node) -> Option<Finding> {
    let initializer = string_prop(ctx.batch, write.id, "initializer")?;
    if !OPEN_PRODUCERS
        .iter()
        .any(|needle| initializer.contains(needle))
    {
        return None;
    }
    let target = string_prop(ctx.batch, write.id, "target")?;
    let path = enclosing_file_path(ctx.batch, write.id)?;
    if is_test_file_path(&path) {
        return None;
    }
    let calls = receiver_calls(ctx, target);
    let close_offset = first_close_offset(ctx, &calls)?;
    let dangling = first_call_after(ctx, &calls, close_offset)?;
    let location = location_from_node(ctx.batch, dangling, path);
    Some(build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.state_machine",
        severity: Severity::Blocker,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{target}` is used after `close()`/`disconnect()`/`release()`"),
        explanation: format!(
            "`{target}` was opened, then closed, then read again — accessing \
             a closed resource raises ValueError / IOError / use-after-free \
             at runtime. Restructure the lifetime so the resource is closed \
             exactly once after the last access."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the resource in a `with` block / `defer close()` / RAII \
             scope so close happens once at the end, or reopen the resource \
             before the post-close access if it is genuinely needed."
                .into(),
        ),
        snippet: initializer.to_owned(),
        weight: 4,
    }))
}

fn receiver_calls(ctx: &RuleContext<'_>, target: &str) -> Vec<NodeId> {
    nodes_of_kind(ctx.batch, NodeKind::Call)
        .filter(|c| string_prop(ctx.batch, c.id, "receiver") == Some(target))
        .map(|c| c.id)
        .collect()
}

fn first_close_offset(ctx: &RuleContext<'_>, calls: &[NodeId]) -> Option<u32> {
    calls
        .iter()
        .filter_map(|id| {
            let method = string_prop(ctx.batch, *id, "method")?;
            if !CLOSE_METHODS.contains(&method) {
                return None;
            }
            let range = range_prop(ctx.batch, *id, "range")?;
            Some(range.start.offset)
        })
        .min()
}

fn first_call_after(ctx: &RuleContext<'_>, calls: &[NodeId], close_offset: u32) -> Option<NodeId> {
    let mut candidates: Vec<(u32, NodeId)> = calls
        .iter()
        .filter_map(|id| {
            let range = range_prop(ctx.batch, *id, "range")?;
            (range.start.offset > close_offset).then_some((range.start.offset, *id))
        })
        .collect();
    candidates.sort_by_key(|(offset, _)| *offset);
    candidates.first().map(|(_, id)| *id)
}

/// Diagnostic helper: borrow a node by id (kept to keep the test helpers
/// of this module independent of the `cc_frontend` re-export).
#[must_use]
#[allow(dead_code)]
pub(crate) fn diag_node(batch: &cc_cpg::CpgWriteBatch, id: NodeId) -> Option<&Node> {
    node_by_id(batch, id)
}
