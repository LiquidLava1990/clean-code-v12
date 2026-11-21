//! Internal helpers shared across Family-5 (concurrency) probes.
//!
//! Re-implements the small set of traversal primitives every Family-5
//! rule needs so the pack stays sibling-independent of `cc-rules-tier0`,
//! `cc-rules-secrets`, `cc-rules-perf`, and `cc-rules-bugs`.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_children, ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinConcurrencyPack;

/// Probe-pack identity stamped on every Family-5 finding.
///
/// `R-ERR-ACTION`: this never fails in normal operation; if a pack id
/// drift is observed in stamping, re-vendor `cc-rules` and rebuild.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinConcurrencyPack::PACK_ID,
        BuiltinConcurrencyPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the `AST_PARENT` chain to the enclosing [`NodeKind::File`] and
/// return its `path` string property. Bounded to 256 hops.
#[must_use]
pub(crate) fn enclosing_file_path(batch: &CpgWriteBatch, mut id: NodeId) -> Option<Utf8PathBuf> {
    for _ in 0..256_u16 {
        if node_kind(batch, id) == Some(NodeKind::File) {
            return string_prop(batch, id, "path").map(Utf8PathBuf::from);
        }
        id = ast_parent(batch, id)?;
    }
    None
}

/// Walk the `AST_PARENT` chain looking for the enclosing
/// [`NodeKind::Function`] / [`NodeKind::Method`] node. Returns `None`
/// when the symbol is module-level.
#[must_use]
pub(crate) fn enclosing_function(batch: &CpgWriteBatch, mut id: NodeId) -> Option<NodeId> {
    for _ in 0..256_u16 {
        let parent = ast_parent(batch, id)?;
        if matches!(
            node_kind(batch, parent),
            Some(NodeKind::Function | NodeKind::Method)
        ) {
            return Some(parent);
        }
        id = parent;
    }
    None
}

/// Build a [`Location`] anchored at the node's `range` property, falling
/// back to the start of the file when the property is missing.
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

/// Best-effort callee text for a [`NodeKind::Call`] node.
///
/// Thin re-export of [`cc_frontend::query::callee_text`] — every pack
/// uses the same canonical merge logic so substring needles see a
/// uniform haystack.
#[must_use]
pub(crate) fn callee_text(batch: &CpgWriteBatch, id: NodeId) -> String {
    cc_frontend::query::callee_text(batch, id)
}

/// True iff `path` is a source file inside a rule-pack crate
/// (`crates/cc-rules-*/src/...`). Probes whose patterns appear in their
/// own remediation strings / fixture data skip these files to avoid
/// rule-on-rule self-flagging.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

/// Best-effort first-argument text for a [`NodeKind::Call`] node.
///
/// Two slot conventions in current frontends: `first_arg_value` (string
/// literal) and `first_arg_name` (identifier reference). Probes treat
/// either as the path argument they care about.
#[must_use]
pub(crate) fn first_arg_text(batch: &CpgWriteBatch, id: NodeId) -> Option<String> {
    for key in ["first_arg_value", "first_arg_name", "first_arg"] {
        if let Some(v) = string_prop(batch, id, key) {
            return Some(v.to_owned());
        }
    }
    None
}

/// True iff the function (or method) marked at `id` is async.
#[must_use]
pub(crate) fn is_async_function(batch: &CpgWriteBatch, id: NodeId) -> bool {
    cc_frontend::query::bool_prop(batch, id, "is_async") == Some(true)
}

/// Collect every descendant [`NodeKind::Call`] under `root` in
/// source-order (sorted by the call's `range.start.offset`). Caller
/// supplies an empty buffer; the helper fills and sorts it.
pub(crate) fn collect_descendant_calls(batch: &CpgWriteBatch, root: NodeId, out: &mut Vec<NodeId>) {
    let mut stack: Vec<NodeId> = ast_children(batch, root).collect();
    while let Some(id) = stack.pop() {
        for child in ast_children(batch, id) {
            stack.push(child);
        }
        if node_kind(batch, id) == Some(NodeKind::Call) {
            out.push(id);
        }
    }
    out.sort_by_key(|id| range_prop(batch, *id, "range").map_or(0, |r| r.start.offset));
}

/// True iff `callee` looks like a lock-acquisition call.
///
/// Closed list across the four supported languages — extend on contact
/// rather than guessing future frameworks.
#[must_use]
pub(crate) fn is_lock_acquire(callee: &str) -> bool {
    let needle = callee;
    needle.ends_with(".lock()")
        || needle.ends_with(".lock")
        || needle.ends_with(".acquire")
        || needle.ends_with(".acquire()")
        || needle.contains("Mutex::lock")
        || needle.contains("RwLock::read")
        || needle.contains("RwLock::write")
        || needle.contains("with_lock")
        || needle.contains("threading.Lock")
        || needle.contains("asyncio.Lock")
}

/// True iff `callee` looks like a thread / async-task spawn.
#[must_use]
pub(crate) fn is_spawn_call(callee: &str) -> bool {
    callee.contains("thread::spawn")
        || callee.contains("tokio::spawn")
        || callee.contains("asyncio.create_task")
        || callee.contains("asyncio.ensure_future")
        || callee.contains("Thread(")
        || callee.contains("threading.Thread")
        || callee.contains("setTimeout")
        || callee.contains("setInterval")
        || callee.contains("Promise.all")
        || callee.contains("go func")
        || callee == "go"
}

/// Adjust a brace-depth counter for one line. Returns the new depth.
/// Centralises the `{` / `}` counting that several Phase-9 Go probes
/// share — the deduplication is itself an S5 canonical-name guarantee.
#[must_use]
pub(crate) fn apply_braces(depth: i32, line: &str) -> i32 {
    let opens = i32::try_from(line.matches('{').count()).unwrap_or(0);
    let closes = i32::try_from(line.matches('}').count()).unwrap_or(0);
    depth + opens - closes
}

/// Find the line index at which the brace block opened on `start_idx`
/// (or shortly after) closes. Used by Go body walkers when they need
/// to scope follow-up scanning to a single function / loop body.
#[must_use]
pub(crate) fn find_matching_brace_end(lines: &[&str], start_idx: usize) -> usize {
    let mut depth: i32 = 0;
    let mut seen_open = false;
    for (idx, line) in lines.iter().enumerate().skip(start_idx) {
        depth = apply_braces(depth, line);
        if line.contains('{') {
            seen_open = true;
        }
        if seen_open && depth <= 0 {
            return idx + 1;
        }
    }
    lines.len()
}

/// True iff `path` ends in `_test.go`. Phase-9 Go probes share this
/// skip-test-file gate.
#[must_use]
pub(crate) fn is_go_test_path(path: &Utf8PathBuf) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_test.go"))
}

/// Collect line-index `[start, end)` ranges for every `func ...` whose
/// declaration line satisfies `header_pred`. Naive brace counter
/// keeps overhead at O(N * avg_line_len). Used by Phase-9 Go probes
/// that need to scope scanning to specific function bodies.
#[must_use]
pub(crate) fn collect_function_ranges(
    lines: &[&str],
    header_pred: impl Fn(&str) -> bool,
) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    let mut depth: i32 = 0;
    let mut start: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if start.is_none()
            && trimmed.starts_with("func ")
            && header_pred(line)
            && line.contains('{')
        {
            start = Some(idx);
            depth = apply_braces(0, line);
            continue;
        }
        if let Some(s) = start {
            depth = apply_braces(depth, line);
            if depth <= 0 {
                out.push((s, idx + 1));
                start = None;
                depth = 0;
            }
        }
    }
    out
}

/// Inputs every Family-5 rule supplies when emitting a [`Finding`].
///
/// Mirrors the named-field constructor pattern used by sibling packs.
#[derive(Debug)]
pub(crate) struct ConcurrencyFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.concurrent.race"`.
    pub rule_id: &'static str,
    /// Severity stamped on the finding.
    pub severity: Severity,
    /// Confidence (0..=1) the rule has in this finding.
    pub confidence: Confidence,
    /// Source location where the issue manifests.
    pub location: Location,
    /// One-line headline shown first in any sink.
    pub headline: String,
    /// Multi-line explanation covering what + why.
    pub explanation: String,
    /// Concrete remediation guidance the user can act on.
    pub remediation: Remediation,
    /// Source-code snippet anchoring the finding (may be empty).
    pub snippet: String,
    /// Blocking-debt weight for score impact.
    pub weight: u32,
}

/// Build a complete [`Finding`] from a [`ConcurrencyFindingBlueprint`].
///
/// `R-ERR-ACTION`: builder failure means a required field is missing —
/// fix the call site, do not paper over with `unwrap_or_default`.
pub(crate) fn build_finding(blueprint: ConcurrencyFindingBlueprint) -> Finding {
    let ConcurrencyFindingBlueprint {
        rule_id,
        severity,
        confidence,
        location,
        headline,
        explanation,
        remediation,
        snippet,
        weight,
    } = blueprint;
    let evidence = Evidence::from_snippet(snippet);
    let message = ActionableMessage::new(headline, explanation, remediation);
    FindingBuilder::new()
        .rule_id(rule_id)
        .category(Category::Concurrent)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-5 finding builder receives all required fields")
}
