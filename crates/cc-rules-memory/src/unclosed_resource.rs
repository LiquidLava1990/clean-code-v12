//! `cc.memory.unclosed_resource` — file / socket / cursor / connection
//! opened without a matching `close()` / `with` / `defer` /
//! try-with-resources / `?`-on-`Result`-from-RAII.
//!
//! Heuristic: enumerate [`NodeKind::Write`] nodes whose `initializer`
//! looks like an opening Call (constructors of files, sockets, cursors,
//! HTTP servers, etc). For each such write:
//!
//! 1. Resolve the enclosing `Function` / `Method` (module-scope writes
//!    are skipped — they're the cache_unbounded shape, not a leak).
//! 2. If the write is inside a `Try` ancestor — assume try-with-resources
//!    or `?`-shaped early-return RAII; skip.
//! 3. If the initializer string contains `with ` / `defer ` / `using ` —
//!    skip (handled by language scope).
//! 4. Look for any [`NodeKind::Call`] whose `receiver` matches the
//!    write's `target` and whose method name is `close` / `shutdown` /
//!    `dispose` / `release` inside the same enclosing function.
//! 5. If no matching close-call exists, fire.
//!
//! Frontends that don't surface `receiver` keep this probe silent rather
//! than emitting false positives — without receiver resolution we
//! cannot tell which call closes which handle.

use cc_cpg::{CpgWriteBatch, Node, NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_parent, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, enclosing_function, has_ancestor_kind, is_test_file_path,
    location_from_node, looks_like_rule_pack_source, MemoryFindingBlueprint,
};

/// Family-6 probe R-MEM-UNCLOSED.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnclosedResourceRule;

const OPEN_PRODUCERS: &[&str] = &[
    "open(",
    "fs.openSync",
    "fs.createReadStream",
    "fs.createWriteStream",
    "File::open",
    "File::create",
    "TcpStream::connect",
    "TcpListener::bind",
    "net.Listen",
    "net.Dial",
    "socket.socket",
    "sqlite3.connect",
    "psycopg2.connect",
    "http.Server",
    "tempfile.NamedTemporaryFile",
];

const CLOSE_METHODS: &[&str] = &["close", "shutdown", "dispose", "release", "drop", "end"];

const SCOPE_HINTS: &[&str] = &["with ", "defer ", "using ", "use("];

impl Rule for UnclosedResourceRule {
    fn rule_id(&self) -> &'static str {
        "cc.memory.unclosed_resource"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Memory
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.7)
    }
    fn description(&self) -> &'static str {
        "resource opened without matching close() / with / defer / try-with-resources"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Write) {
            if let Some(finding) = check_write(ctx, node) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_write(ctx: &RuleContext<'_>, write: &Node) -> Option<Finding> {
    let initializer = string_prop(ctx.batch, write.id, "initializer")?;
    if !is_open_producer(initializer) {
        return None;
    }
    if SCOPE_HINTS.iter().any(|hint| initializer.contains(hint)) {
        return None;
    }
    let target = string_prop(ctx.batch, write.id, "target")?;
    let path = enclosing_file_path(ctx.batch, write.id)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    if has_ancestor_kind(ctx.batch, write.id, NodeKind::Try) {
        return None;
    }
    let scope = enclosing_function(ctx.batch, write.id)?;
    if has_close_in_scope(ctx.batch, scope, target) {
        return None;
    }
    let location = location_from_node(ctx.batch, write.id, path);
    Some(build_finding(MemoryFindingBlueprint {
        rule_id: "cc.memory.unclosed_resource",
        severity: Severity::Required,
        confidence: Confidence::new(0.7),
        location,
        headline: format!("`{target}` opened without close() / with / defer / try"),
        explanation: format!(
            "`{target}` is bound to a resource-opening call but no matching \
             `close()` / `shutdown()` / `release()` is reachable in the same \
             function. Leaks tend to manifest only under load — flag now."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Wrap in `with` (Python) / `defer close()` (Go) / `try-with-resources` \
             (Java) / let RAII destructor handle it (Rust). If the handle \
             genuinely escapes the function, return it explicitly so the \
             caller owns the close."
                .into(),
        ),
        snippet: initializer.to_owned(),
        weight: 3,
    }))
}

fn is_open_producer(initializer: &str) -> bool {
    OPEN_PRODUCERS
        .iter()
        .any(|needle| initializer.contains(needle))
}

fn has_close_in_scope(batch: &CpgWriteBatch, scope: NodeId, target: &str) -> bool {
    nodes_of_kind(batch, NodeKind::Call).any(|call| {
        let same_scope = walks_to(batch, call.id, scope);
        let receiver_matches = string_prop(batch, call.id, "receiver") == Some(target);
        let method_closes =
            string_prop(batch, call.id, "method").is_some_and(|m| CLOSE_METHODS.contains(&m));
        same_scope && receiver_matches && method_closes
    })
}

fn walks_to(batch: &CpgWriteBatch, mut id: NodeId, target: NodeId) -> bool {
    if id == target {
        return true;
    }
    for _ in 0..256_u16 {
        let Some(parent) = ast_parent(batch, id) else {
            return false;
        };
        if parent == target {
            return true;
        }
        // Stop walking when we cross another Function / Method scope.
        if matches!(
            node_kind(batch, parent),
            Some(NodeKind::Function | NodeKind::Method)
        ) && parent != target
        {
            return false;
        }
        id = parent;
    }
    false
}
