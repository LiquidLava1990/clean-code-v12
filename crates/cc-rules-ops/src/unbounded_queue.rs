//! `cc.ops.unbounded_queue` — producer/consumer without max size.
//!
//! Heuristic: enumerate every [`NodeKind::Call`] node and match the
//! callee against `QUEUE_CONSTRUCTOR_CALLEES`. The constructor names
//! in the table are the *unbounded* spellings; bounded variants
//! (`Queue(maxsize=N)`, `mpsc::channel(N)`, `make(chan T, N)`) lift
//! into a different callee text and so escape the match.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, call_args_text, callee_text, enclosing_file_path, location_from_node,
    matches_any, OpsFindingBlueprint, QUEUE_CONSTRUCTOR_CALLEES,
};

/// Family-12 probe `cc.ops.unbounded_queue`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnboundedQueueRule;

impl Rule for UnboundedQueueRule {
    fn rule_id(&self) -> &'static str {
        "cc.ops.unbounded_queue"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Ops
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "queue / channel constructed without a bounded capacity"
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
    let callee = callee_text(ctx.batch, id);
    if !matches_any(&callee, QUEUE_CONSTRUCTOR_CALLEES) {
        return None;
    }
    if has_bounded_argument(&call_args_text(ctx.batch, id)) {
        return None;
    }
    let path = enclosing_file_path(ctx.batch, id)?;
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(OpsFindingBlueprint {
        rule_id: "cc.ops.unbounded_queue",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{}` is unbounded", short_callee(&callee)),
        explanation: "An unbounded queue lets a slow consumer accumulate \
             messages without limit. Memory grows until the OS kills the \
             process. Backpressure must be explicit — pick a maximum and \
             decide how to handle the overflow (drop, block, error)."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Use the bounded variant: `queue.Queue(maxsize=N)` / \
             `asyncio.Queue(maxsize=N)` / `crossbeam::channel::bounded(N)` / \
             `mpsc::channel(N)` / `make(chan T, N)`. Choose `N` based on \
             expected burst size and memory budget."
                .into(),
        ),
        snippet: callee.clone(),
        weight: 2,
    }))
}

/// True iff the call's argument text already declares a bounded
/// capacity. Defensive — `crossbeam::channel::unbounded` would never
/// carry a `maxsize=` arg, but `Queue` and `asyncio.Queue` accept
/// optional bounded args via the same constructor name we matched on.
fn has_bounded_argument(args: &str) -> bool {
    let lower = args.to_ascii_lowercase();
    lower.contains("maxsize=")
        || lower.contains("max_size=")
        || lower.contains("capacity=")
        || lower.contains("bound=")
}

fn short_callee(text: &str) -> &str {
    text.split_whitespace().next().unwrap_or(text)
}
