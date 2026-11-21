//! `cc.perf.sync_in_async` — blocking sync I/O inside an async function.
//!
//! Algorithm: scan every [`NodeKind::Function`] / [`NodeKind::Method`]
//! whose `is_async` lang_ext bool is true, walk its descendants for
//! [`NodeKind::Call`] nodes, and match the callee text against a closed
//! list of known-blocking sync stdlib calls. The whole list is checked
//! per call, but the per-call work is O(text-length) so the rule stays
//! cheap.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, bool_prop, node_kind, nodes_of_kind};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, location_from_node, PerfFindingBlueprint,
};

/// Family-2 perf rule R-PERF-SYNC-IN-ASYNC.
#[derive(Debug, Default, Clone, Copy)]
pub struct SyncInAsyncRule;

/// Closed list of sync stdlib calls that should never run on an async
/// runtime. Each entry is matched as a substring on the callee text.
const BLOCKING_CALLS: &[&str] = &[
    "time.sleep",
    "requests.get",
    "requests.post",
    "urllib.request.urlopen",
    "socket.recv",
    "subprocess.run",
    "fs.readFileSync",
    "fs.writeFileSync",
    "os.ReadFile",
    "ioutil.ReadFile",
    "std::fs::read",
    "std::fs::write",
    "std::thread::sleep",
];

impl Rule for SyncInAsyncRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.sync_in_async"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "blocking sync stdlib call inside an async function"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if bool_prop(ctx.batch, node.id, "is_async") != Some(true) {
                    continue;
                }
                collect_blocking_calls(ctx, node.id, &mut out);
            }
        }
        out
    }
}

/// DFS the function body once, emitting one finding per blocking call.
fn collect_blocking_calls(ctx: &RuleContext<'_>, function: NodeId, out: &mut Vec<Finding>) {
    let mut stack: Vec<NodeId> = ast_children(ctx.batch, function).collect();
    while let Some(id) = stack.pop() {
        for child in ast_children(ctx.batch, id) {
            stack.push(child);
        }
        if node_kind(ctx.batch, id) != Some(NodeKind::Call) {
            continue;
        }
        let text = callee_text(ctx.batch, id);
        let Some(hit) = BLOCKING_CALLS.iter().find(|needle| text.contains(*needle)) else {
            continue;
        };
        if let Some(finding) = emit(ctx, id, hit) {
            out.push(finding);
        }
    }
}

fn emit(ctx: &RuleContext<'_>, call: NodeId, blocking: &str) -> Option<Finding> {
    let path = enclosing_file_path(ctx.batch, call)?;
    let location = location_from_node(ctx.batch, call, path);
    Some(build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.sync_in_async",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("blocking call `{blocking}` inside async function"),
        explanation: format!(
            "`{blocking}` parks the entire async runtime — every other coroutine \
             stalls until it returns. Use the runtime-native async equivalent \
             (e.g. `asyncio.sleep`, `httpx.AsyncClient`, `tokio::fs::read`) or \
             offload via `asyncio.to_thread` / `tokio::task::spawn_blocking`."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace the blocking call with the async-native equivalent, or wrap \
             it in `to_thread` / `spawn_blocking` if no async port exists."
                .into(),
        ),
        snippet: String::new(),
        weight: 2,
    }))
}
