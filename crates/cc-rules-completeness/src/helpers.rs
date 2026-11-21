//! Internal helpers shared across Family-25 probes.
//!
//! - [`CompletenessFindingBlueprint`] — the named-field finding builder
//!   every probe uses (mirrors `Tier0FindingBlueprint`).
//! - Source-text scan helpers (`function_body_text`, `body_contains_any`).
//! - Heuristic classifiers
//!   (`looks_like_io_call` / `looks_like_external_dep_call` /
//!   `is_emit_callee` / `is_subscribe_callee` / `is_state_change_name`
//!   / `is_rpc_entry_name` / `has_decorator_named`).
//!
//! Phase-2 stance: every classifier is a heuristic over function names,
//! decorator strings, and source-text substring matches. The full LLM
//! verification path lands in Phase 5.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, EdgeKind, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{
    ast_children, ast_parent, incoming_edges_of_kind, node_by_id, node_kind, range_prop,
    string_prop,
};

use crate::pack::BuiltinCompletenessPack;

/// Probe-pack identity stamped on every Family-25 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinCompletenessPack::PACK_ID,
        BuiltinCompletenessPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the AST_PARENT chain up to the enclosing [`NodeKind::File`] and
/// return the file's `path` property.
#[must_use]
pub(crate) fn enclosing_file_path(batch: &CpgWriteBatch, mut id: NodeId) -> Option<Utf8PathBuf> {
    for _ in 0..256_u16 {
        if let Some(node) = node_by_id(batch, id) {
            if node.kind == NodeKind::File {
                return string_prop(batch, id, "path").map(Utf8PathBuf::from);
            }
        }
        id = ast_parent(batch, id)?;
    }
    None
}

/// Build a [`Location`] anchored at the node's `range` property.
pub(crate) fn location_from_node(batch: &CpgWriteBatch, id: NodeId, file: Utf8PathBuf) -> Location {
    let (start, end) = range_prop(batch, id, "range").map_or_else(
        || {
            let zero = Position::new(1, 1, 0);
            (zero, zero)
        },
        |r| {
            (
                Position::new(r.start.line, r.start.column, r.start.offset),
                Position::new(r.end.line, r.end.column, r.end.offset),
            )
        },
    );
    Location {
        file,
        start,
        end,
        node_id: Some(cc_finding::NodeId::new(id.get().to_string())),
        function_qualified_name: string_prop(batch, id, "name").map(str::to_owned),
    }
}

/// Inputs every Family-25 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct CompletenessFindingBlueprint {
    /// Stable rule identifier (e.g. `"cc.observe.public_fn_untraced"`).
    pub rule_id: &'static str,
    /// Top-level category bucket.
    pub category: Category,
    /// Severity to stamp on the finding.
    pub severity: Severity,
    /// Confidence (0..=1).
    pub confidence: Confidence,
    /// Source location of the issue.
    pub location: Location,
    /// One-line headline.
    pub headline: String,
    /// Multi-line explanation: what + why.
    pub explanation: String,
    /// Concrete remediation guidance.
    pub remediation: Remediation,
    /// Source snippet anchoring the finding.
    pub snippet: String,
    /// Blocking-debt weight.
    pub weight: u32,
}

/// Build a complete [`Finding`] from a [`CompletenessFindingBlueprint`].
pub(crate) fn build_finding(bp: CompletenessFindingBlueprint) -> Finding {
    let evidence = Evidence::from_snippet(bp.snippet);
    let message = ActionableMessage::new(bp.headline, bp.explanation, bp.remediation);
    FindingBuilder::new()
        .rule_id(bp.rule_id)
        .category(bp.category)
        .location(bp.location)
        .message(message)
        .evidence(evidence)
        .severity(bp.severity)
        .confidence(bp.confidence.get())
        .cost(CostClaim::BlockingDebt { weight: bp.weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-25 finding builder receives all required fields")
}

// ---------- source-text helpers -------------------------------------------

/// Read the source bytes for a function's `range` property and return
/// them as a UTF-8 string. Returns `None` if range / source is missing.
#[must_use]
pub(crate) fn function_body_text(
    batch: &CpgWriteBatch,
    id: NodeId,
    source: &dyn cc_rules::SourceTable,
) -> Option<String> {
    let path = enclosing_file_path(batch, id)?;
    let bytes = source.get(&path);
    let range = range_prop(batch, id, "range")?;
    let s = (range.start.offset as usize).min(bytes.len());
    let e = (range.end.offset as usize).min(bytes.len()).max(s);
    if s >= e {
        return None;
    }
    std::str::from_utf8(&bytes[s..e]).ok().map(str::to_owned)
}

/// True iff `text` contains any of `needles` as a substring.
#[must_use]
pub(crate) fn body_contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

// ---------- structural helpers --------------------------------------------

/// True iff `id` is a `Function` or `Method` whose AST parent is a
/// `File` or `Module` (i.e. a top-level definition).
#[must_use]
pub(crate) fn is_top_level_fn(batch: &CpgWriteBatch, id: NodeId) -> bool {
    matches!(
        node_kind(batch, id),
        Some(NodeKind::Function | NodeKind::Method)
    ) && matches!(
        ast_parent(batch, id).and_then(|p| node_kind(batch, p)),
        Some(NodeKind::File | NodeKind::Module)
    )
}

/// True iff the function appears `pub` / exported. Conservative — uses
/// the `is_pub` / `is_export` / `visibility` props the frontends emit.
#[must_use]
pub(crate) fn is_public_fn(batch: &CpgWriteBatch, id: NodeId) -> bool {
    if cc_frontend::query::bool_prop(batch, id, "is_pub").unwrap_or(false) {
        return true;
    }
    if cc_frontend::query::bool_prop(batch, id, "is_export").unwrap_or(false) {
        return true;
    }
    matches!(string_prop(batch, id, "visibility"), Some("public" | "pub"))
}

/// True iff the function carries any decorator whose name contains any
/// of `substrs` (case-sensitive substring match).
#[must_use]
pub(crate) fn has_decorator_containing(
    batch: &CpgWriteBatch,
    fn_id: NodeId,
    substrs: &[&str],
) -> bool {
    decorators_of(batch, fn_id).any(|name| substrs.iter().any(|s| name.contains(s)))
}

/// Iterate every decorator name attached to `fn_id` via incoming
/// AST_PARENT edges. Decorators are siblings; we treat any
/// [`NodeKind::Decorator`] child of the same parent that precedes the
/// function in source order as belonging to it. Phase-2 simplification:
/// we accept *any* incoming `Decorator` AST_PARENT child of the
/// function itself OR a `Decorator` sibling under the same parent.
fn decorators_of<'b>(
    batch: &'b CpgWriteBatch,
    fn_id: NodeId,
) -> impl Iterator<Item = &'b str> + 'b {
    let parent = ast_parent(batch, fn_id);
    incoming_edges_of_kind(batch, fn_id, EdgeKind::AST_PARENT)
        .filter(move |e| node_kind(batch, e.from) == Some(NodeKind::Decorator))
        .map(|e| e.from)
        .chain(parent.into_iter().flat_map(move |p| {
            ast_children(batch, p)
                .filter(move |c| node_kind(batch, *c) == Some(NodeKind::Decorator))
        }))
        .filter_map(|d| string_prop(batch, d, "name"))
}

/// True iff `name` looks like a known I/O callee.
///
/// Phase-2 heuristic — a small list of well-known idioms across Python /
/// Rust / Go / TypeScript. Not exhaustive; tuned for low false-positive
/// rate on the kernel's own self-host pass.
#[must_use]
pub(crate) fn looks_like_io_call(name: &str) -> bool {
    const IO_NEEDLES: &[&str] = &[
        "fs::read",
        "fs::write",
        "fs.read",
        "fs.write",
        "open(",
        "socket.recv",
        "socket::recv",
        "send(",
        "recv(",
        "db.execute",
        "db::execute",
        "execute_query",
        "fetch(",
        "request(",
        "http.get",
        "http.post",
        "requests.",
        "urllib.",
        "reqwest::",
        "tokio::fs",
        "std::fs::",
        "ioutil.Read",
        "os.Open",
    ];
    IO_NEEDLES.iter().any(|n| name.contains(n))
}

/// True iff `name` looks like a call into an external dependency boundary
/// (anything that benefits from a circuit breaker / rate limit).
#[must_use]
pub(crate) fn looks_like_external_dep_call(name: &str) -> bool {
    const EXT_NEEDLES: &[&str] = &[
        "http.",
        "https.",
        "client.",
        "Client::",
        "rpc.",
        "grpc.",
        "rabbit",
        "kafka",
        "redis",
        "stripe",
        "twilio",
        "aws_sdk",
        "boto3",
        "openai",
        "anthropic",
    ];
    EXT_NEEDLES.iter().any(|n| name.contains(n))
}

/// True iff a callee name represents an event emit.
#[must_use]
pub(crate) fn is_emit_callee(name: &str) -> bool {
    const EMIT_NEEDLES: &[&str] = &[
        "bus.emit",
        "EventBus.emit",
        "EventBus::publish",
        "publish",
        "emit(",
        "dispatch(",
        ".send(",
        "broadcast(",
    ];
    EMIT_NEEDLES.iter().any(|n| name.contains(n))
}

/// True iff a callee name represents an event subscription.
#[must_use]
pub(crate) fn is_subscribe_callee(name: &str) -> bool {
    const SUB_NEEDLES: &[&str] = &[
        "on_event",
        "subscribe",
        "addEventListener",
        "register_handler",
        "@on(",
        ".on(",
    ];
    SUB_NEEDLES.iter().any(|n| name.contains(n))
}

/// True iff a function name looks like a state-change verb.
#[must_use]
pub(crate) fn is_state_change_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("save_")
        || lower.starts_with("update_")
        || lower.starts_with("delete_")
        || lower.starts_with("publish_")
        || lower.starts_with("create_")
        || lower.starts_with("write_")
        || lower.starts_with("commit_")
}

/// True iff a function name looks like an RPC entry point.
#[must_use]
pub(crate) fn is_rpc_entry_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("handle_")
        || lower.ends_with("_endpoint")
        || lower.ends_with("_handler")
        || lower.ends_with("_route")
        || lower == "handle"
}

/// Extract the first string-literal argument of a `Call`/`Return` node
/// from its `name = "..."` decorator argument property if present.
#[must_use]
pub(crate) fn decorator_arg_name(batch: &CpgWriteBatch, decorator_id: NodeId) -> Option<&str> {
    string_prop(batch, decorator_id, "arg_name")
}

/// True iff `path` is a source file inside a rule-pack crate
/// (`crates/cc-rules-*/src/...`). The bare-re-raise probe skips these
/// because rule implementations legitimately embed pattern strings like
/// `"except Exception: raise"` as detector needles — flagging a probe
/// for owning the shape it scans for is rule-on-rule noise.
///
/// Phase-2 conservative path skip — TODO Phase 5: replace with AST-level
/// detection (Try → Handler → Raise without `from`) once frontends emit
/// a stable bare-re-raise marker on every Handler node.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}
