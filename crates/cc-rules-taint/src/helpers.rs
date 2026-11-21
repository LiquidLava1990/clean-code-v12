//! Internal helpers shared across Family-4 (taint) probes.
//!
//! This module owns the per-function tainted-set construction
//! ([`build_tainted_set`]) and the static SOURCE / SANITIZER tables.
//! Per-rule sink tables live next to each rule.

use std::collections::{HashSet, VecDeque};

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{
    ast_children, ast_parent, node_by_id, node_kind, range_prop, string_prop,
};
use cc_rules::SourceTable;

use crate::pack::BuiltinTaintPack;

/// Probe-pack identity stamped on every Family-4 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinTaintPack::PACK_ID,
        BuiltinTaintPack::PACK_SEMVER,
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

/// Build a [`Location`] anchored at the node's `range` property,
/// falling back to the start-of-file when the property is missing.
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

/// Inputs every Family-4 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct TaintFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.taint.sql_injection"`.
    pub rule_id: &'static str,
    /// Top-level category — always [`Category::Taint`] for this pack.
    pub category: Category,
    /// Severity — always [`Severity::Blocker`] for this pack.
    pub severity: Severity,
    /// Confidence (0..=1) the rule has in this finding.
    pub confidence: Confidence,
    /// Source location where the sink fires.
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

/// Build a complete [`Finding`] from a [`TaintFindingBlueprint`].
pub(crate) fn build_finding(blueprint: TaintFindingBlueprint) -> Finding {
    let TaintFindingBlueprint {
        rule_id,
        category,
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
        .category(category)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-4 finding builder receives all required fields")
}

// ---------------------------------------------------------------------------
// Source / sink / sanitizer tables
// ---------------------------------------------------------------------------

/// Web-context untrusted-input sources — request bodies, query params,
/// and HTTP extractors. These are the canonical "attacker over the
/// network" sources where path-traversal, SSRF, and similar
/// remote-attack flows are real.
///
/// Each entry is matched against `Call.callee_ref` in two ways: exact
/// equality and `ends_with` (so `request.GET` matches both
/// `request.GET` directly and qualified forms like `flask.request.GET`).
pub(crate) const SOURCES_WEB: &[&str] = &[
    // Flask / FastAPI / Django request shapes
    "request.GET",
    "request.POST",
    "request.form",
    "request.args",
    "request.params",
    "request.json",
    "request.values",
    "request.data",
    "request.body",
    // Express
    "req.body",
    "req.query",
    "req.params",
    // Go net/http
    "r.URL.Query",
    "r.FormValue",
    "r.PostFormValue",
    // axum (Rust) — extractors usually appear as types; but Json::from_request
    "axum::extract::Query",
    "axum::Json",
    "Query::from_request",
    "Json::from_request",
    // Generic interactive untrusted-input (TTY / stdin in a server context)
    "input",
    "raw_input",
    "sys.stdin.read",
];

/// CLI / environment untrusted-input sources — argv and env reads.
/// Reading the file the user named on the CLI is the *feature* of a
/// developer tool, not a vulnerability, so path-traversal probes
/// deliberately exclude this table. Other rules (sqli, xss, repr, etc.)
/// remain context-independent and combine it with [`SOURCES_WEB`].
///
/// Currently no rule consumes `SOURCES_CLI` directly — every
/// non-traversal rule prefers the union [`SOURCES_ANY`] for parity
/// with prior behaviour. The constant is retained so a future probe
/// (e.g. an "argv-only" environment-leak check) can reach for it
/// without re-deriving the split.
#[allow(dead_code)]
pub(crate) const SOURCES_CLI: &[&str] = &[
    "os.Args",
    "std::env::args",
    "std::env::args_os",
    "process.argv",
    "argparse.parse_args",
    // env-var reads — process-supplied, but still untrusted relative
    // to the running code.
    "os.environ.get",
    "os.getenv",
    "std::env::var",
    "process.env",
];

/// Union of [`SOURCES_WEB`] and [`SOURCES_CLI`] — the default source
/// table for context-independent rules (`sqli`, `xss`,
/// `command_injection`, `repr_on_untrusted`, `ssrf`,
/// `unsafe_deserialization`).
pub(crate) const SOURCES_ANY: &[&str] = &[
    // --- web sources (mirrored from SOURCES_WEB) ---
    "request.GET",
    "request.POST",
    "request.form",
    "request.args",
    "request.params",
    "request.json",
    "request.values",
    "request.data",
    "request.body",
    "req.body",
    "req.query",
    "req.params",
    "r.URL.Query",
    "r.FormValue",
    "r.PostFormValue",
    "axum::extract::Query",
    "axum::Json",
    "Query::from_request",
    "Json::from_request",
    "input",
    "raw_input",
    "sys.stdin.read",
    // --- cli + env sources (mirrored from SOURCES_CLI) ---
    "os.Args",
    "std::env::args",
    "std::env::args_os",
    "process.argv",
    "argparse.parse_args",
    "os.environ.get",
    "os.getenv",
    "std::env::var",
    "process.env",
];

/// Sanitizer callees — taint set is stripped of every identifier the
/// call mentions when one of these fires.
pub(crate) const SANITIZERS: &[&str] = &[
    // HTML escaping
    "html.escape",
    "markupsafe.escape",
    "bleach.clean",
    "escape",
    // Path normalization
    "os.path.normpath",
    "os.path.realpath",
    "Path::canonicalize",
    "realpath",
    "path.resolve",
    // SQL parameterization helpers
    "sqlalchemy.text",
    "psycopg2.sql.Identifier",
    "psycopg2.sql.Literal",
    // Shell quoting
    "shlex.quote",
    "shell_escape",
    // URL parsing / allow-list
    "urllib.parse.urlparse",
    "url.parse",
    // Generic validators users may write
    "validate_input",
    "sanitize",
    "sanitize_input",
];

/// True iff `callee_ref` matches any `pattern` in `table` either by
/// exact equality or as a trailing dotted/qualified suffix.
#[must_use]
pub(crate) fn callee_matches(callee_ref: &str, table: &[&str]) -> bool {
    table.iter().any(|p| matches_callee_pattern(callee_ref, p))
}

/// Debug-format placeholder substrings inspected by
/// [`call_uses_debug_format`]. Covers Rust (`{:?}`, `{:#?}`, `{:?#}`),
/// Python (`%r`, `!r`), and Ruby (`#inspect`).
const DEBUG_FORMAT_MARKERS: &[&str] = &["{:?}", "{:#?}", "{:?#}", "%r", "!r", ".inspect"];

/// True iff the source span covered by `call`'s `range` property
/// contains a debug-format placeholder.
///
/// Used as a [`SinkArgCheck`] for `cc.taint.repr_on_untrusted` so that
/// a tainted value passed through a Display-format sink
/// (`format!("{}", x)`, `println!("{}", x)`, `tracing::info!("user={}", x)`)
/// is *not* flagged. Only a debug placeholder leaks the inner shape and
/// triggers invariant R-05.
#[must_use]
pub(crate) fn call_uses_debug_format(
    batch: &CpgWriteBatch,
    source: &dyn SourceTable,
    path: &Utf8PathBuf,
    call: NodeId,
) -> bool {
    let Some(range) = range_prop(batch, call, "range") else {
        // No range — can't grep, so fall back to FIRE so a real R-05
        // is never silently dropped just because of a missing prop.
        // Phase-3 production batches always populate ranges; this
        // path is mostly exercised by unit-test fixtures.
        return true;
    };
    let bytes = source.get(path.as_path());
    let start = range.start.offset as usize;
    let end = range.end.offset as usize;
    let Some(slice) = bytes.get(start..end) else {
        // Range out of bounds for the source slice — skip silently.
        // The 57-finding kernel regression all came through this path
        // when the macro span exceeded the cached byte range; default
        // to no-op rather than re-creating the false-positive flood.
        return false;
    };
    let Ok(text) = std::str::from_utf8(slice) else {
        return false;
    };
    DEBUG_FORMAT_MARKERS.iter().any(|m| text.contains(m))
}

fn matches_callee_pattern(callee_ref: &str, pattern: &str) -> bool {
    if callee_ref == pattern {
        return true;
    }
    if let Some(suffix) = callee_ref.strip_suffix(pattern) {
        return suffix.is_empty() || suffix.ends_with('.') || suffix.ends_with("::");
    }
    false
}

// ---------------------------------------------------------------------------
// Per-function tainted-set construction
// ---------------------------------------------------------------------------

/// Set of variable names known to carry untrusted input within a single
/// function body. Keyed by identifier text — Phase-3 has no symbol
/// resolution, so shadowing is approximate.
pub(crate) type TaintedSet = HashSet<String>;

/// Build the tainted-name set for a single `Function` / `Method` node
/// against the supplied `sources` table.
///
/// The traversal is a top-down BFS over AST_PARENT children. Three
/// propagation rules apply, in order:
///
/// 1. A `Call` whose callee matches `sources` and whose parent is a
///    `Write` taints the write's `target`.
/// 2. A `Write` whose RHS subtree mentions an already-tainted
///    Identifier name taints the write's `target`.
/// 3. A `Call` whose callee matches [`SANITIZERS`] removes every
///    Identifier name in its argument subtree from the set.
pub(crate) fn build_tainted_set(
    batch: &CpgWriteBatch,
    function: NodeId,
    sources: &[&str],
    seed_parameters: bool,
) -> TaintedSet {
    let descendants = collect_descendants_in_order(batch, function);
    let mut tainted: TaintedSet = HashSet::new();
    if seed_parameters {
        seed_tainted_from_parameters(batch, function, &mut tainted);
    }
    // Pass 1: source calls taint their enclosing Write target.
    for id in &descendants {
        if matches!(node_kind(batch, *id), Some(NodeKind::Call)) {
            seed_tainted_from_source_call(batch, *id, sources, &mut tainted);
        }
    }
    // Pass 2: writes whose RHS mentions a tainted name propagate.
    // Run to a fixed point so chains like `a = src(); b = a; c = b`
    // taint every step.
    propagate_writes(batch, &descendants, &mut tainted);
    // Pass 3: sanitizers strip identifier names from the set.
    for id in &descendants {
        if matches!(node_kind(batch, *id), Some(NodeKind::Call)) {
            apply_sanitizer_call(batch, *id, &mut tainted);
        }
    }
    tainted
}

fn propagate_writes(batch: &CpgWriteBatch, descendants: &[NodeId], tainted: &mut TaintedSet) {
    for _ in 0..16_u8 {
        let before = tainted.len();
        for id in descendants {
            if matches!(node_kind(batch, *id), Some(NodeKind::Write)) {
                process_write_for_taint(batch, *id, tainted);
            }
        }
        if tainted.len() == before {
            break;
        }
    }
}

/// Many web-framework handlers receive untrusted input directly via
/// their parameters (e.g. axum extractors, Express handlers). Treat
/// every parameter name as initially tainted.
fn seed_tainted_from_parameters(batch: &CpgWriteBatch, function: NodeId, tainted: &mut TaintedSet) {
    for child in ast_children(batch, function) {
        if matches!(node_kind(batch, child), Some(NodeKind::Parameter)) {
            if let Some(name) = string_prop(batch, child, "name") {
                tainted.insert(name.to_owned());
            }
        }
    }
}

/// Apply a per-call action when its callee matches `table`. Returns
/// silently when the call has no callee, when the callee does not match
/// the table, or when the action chooses not to mutate the set.
fn with_matching_callee<F>(batch: &CpgWriteBatch, call: NodeId, table: &[&str], action: F)
where
    F: FnOnce(&CpgWriteBatch, NodeId),
{
    let Some(callee) = string_prop(batch, call, "callee_ref") else {
        return;
    };
    if !callee_matches(callee, table) {
        return;
    }
    action(batch, call);
}

/// Pass 1: a source-call taints the enclosing Write target.
fn seed_tainted_from_source_call(
    batch: &CpgWriteBatch,
    call: NodeId,
    sources: &[&str],
    tainted: &mut TaintedSet,
) {
    with_matching_callee(batch, call, sources, |batch, call| {
        if let Some(target) = enclosing_write_target(batch, call) {
            tainted.insert(target);
        }
    });
}

/// Pass 3: a sanitizer-call strips every identifier name in its arg
/// subtree from the tainted set.
fn apply_sanitizer_call(batch: &CpgWriteBatch, call: NodeId, tainted: &mut TaintedSet) {
    with_matching_callee(batch, call, SANITIZERS, |batch, call| {
        for name in identifier_names_in_subtree(batch, call) {
            tainted.remove(&name);
        }
    });
}

/// Step 2: a `Write` whose RHS mentions a tainted name taints its
/// target.
fn process_write_for_taint(batch: &CpgWriteBatch, write: NodeId, tainted: &mut TaintedSet) {
    let Some(target) = string_prop(batch, write, "target") else {
        return;
    };
    if rhs_subtree_mentions_tainted(batch, write, tainted) {
        tainted.insert(target.to_owned());
    }
}

/// Walk up to the closest enclosing `Write` ancestor and return its
/// `target` prop. Used for `x = source()` patterns.
fn enclosing_write_target(batch: &CpgWriteBatch, mut id: NodeId) -> Option<String> {
    for _ in 0..32_u16 {
        let parent = ast_parent(batch, id)?;
        if matches!(node_kind(batch, parent), Some(NodeKind::Write)) {
            return string_prop(batch, parent, "target").map(str::to_owned);
        }
        id = parent;
    }
    None
}

/// True iff the RHS subtree of `write` references any name in `tainted`.
fn rhs_subtree_mentions_tainted(
    batch: &CpgWriteBatch,
    write: NodeId,
    tainted: &TaintedSet,
) -> bool {
    identifier_names_in_subtree(batch, write)
        .iter()
        .any(|n| tainted.contains(n))
}

/// Collect every Identifier `name` reachable from `root` via AST_PARENT
/// (root excluded).
pub(crate) fn identifier_names_in_subtree(batch: &CpgWriteBatch, root: NodeId) -> Vec<String> {
    let mut names = Vec::new();
    for id in collect_descendants_in_order(batch, root) {
        if id == root {
            continue;
        }
        if matches!(node_kind(batch, id), Some(NodeKind::Identifier)) {
            if let Some(name) = string_prop(batch, id, "name") {
                names.push(name.to_owned());
            }
        }
    }
    names
}

/// BFS list of `root` plus every AST descendant in discovery order.
pub(crate) fn collect_descendants_in_order(batch: &CpgWriteBatch, root: NodeId) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut queue: VecDeque<NodeId> = VecDeque::new();
    queue.push_back(root);
    let mut seen: HashSet<u64> = HashSet::new();
    seen.insert(root.get());
    while let Some(id) = queue.pop_front() {
        out.push(id);
        for child in ast_children(batch, id) {
            if seen.insert(child.get()) {
                queue.push_back(child);
            }
        }
    }
    out
}

/// True iff any Identifier in the subtree rooted at `call` carries a
/// `name` that lives in `tainted`, OR any nested Call's callee matches
/// the supplied `sources` table (covering the inline
/// `sink(source(...))` pattern where the value never gets bound to a
/// local variable).
#[must_use]
pub(crate) fn call_has_tainted_arg(
    batch: &CpgWriteBatch,
    call: NodeId,
    tainted: &TaintedSet,
    sources: &[&str],
) -> bool {
    if identifier_names_in_subtree(batch, call)
        .iter()
        .any(|n| tainted.contains(n))
    {
        return true;
    }
    subtree_contains_source_call(batch, call, sources)
}

/// True iff any descendant `Call` of `root` (excluding `root` itself)
/// has a callee matching `sources`. Returns `false` if a SANITIZER call
/// appears anywhere in `root`'s subtree as well — the conservative
/// Phase-3 approximation of "the source flows through a sanitizer".
fn subtree_contains_source_call(batch: &CpgWriteBatch, root: NodeId, sources: &[&str]) -> bool {
    let descendants = collect_descendants_in_order(batch, root);
    let mut has_source = false;
    let mut has_sanitizer = false;
    for id in &descendants {
        if *id == root {
            continue;
        }
        if !matches!(node_kind(batch, *id), Some(NodeKind::Call)) {
            continue;
        }
        let Some(callee) = string_prop(batch, *id, "callee_ref") else {
            continue;
        };
        if callee_matches(callee, sources) {
            has_source = true;
        }
        if callee_matches(callee, SANITIZERS) {
            has_sanitizer = true;
        }
    }
    has_source && !has_sanitizer
}

/// Iterate every `Function` and `Method` node id in the batch.
pub(crate) fn function_node_ids(batch: &CpgWriteBatch) -> Vec<NodeId> {
    let mut out = Vec::new();
    for n in batch.nodes() {
        if matches!(n.kind, NodeKind::Function | NodeKind::Method) {
            out.push(n.id);
        }
    }
    out
}

/// Optional per-rule sink-arg predicate. Returns `true` when the
/// matched sink call should be allowed to fire, `false` to skip
/// silently. Used by [`repr_on_untrusted`](crate::repr_on_untrusted) to
/// restrict format-style sinks to debug-format placeholders only.
pub(crate) type SinkArgCheck =
    fn(&CpgWriteBatch, &dyn SourceTable, &Utf8PathBuf, NodeId, &str) -> bool;

/// Per-rule scan configuration shared by every Family-4 probe.
///
/// Each rule supplies the static sink table + message + remediation;
/// the scaffold ([`run_taint_rule`]) handles per-function tainted-set
/// construction and sink iteration uniformly.
pub(crate) struct TaintRuleSpec {
    /// Stable rule id, e.g. `"cc.taint.sql_injection"`.
    pub rule_id: &'static str,
    /// Source table the rule cares about. Defaults at the call site to
    /// [`SOURCES_ANY`]; rules that should ignore CLI argv (e.g.
    /// `cc.taint.path_traversal`) pass [`SOURCES_WEB`] instead.
    pub sources: &'static [&'static str],
    /// Static sink callee patterns. Matched via [`callee_matches`].
    pub sinks: &'static [&'static str],
    /// Confidence the rule emits (0..=1).
    pub confidence: f32,
    /// Blocking-debt weight per finding.
    pub weight: u32,
    /// Builds (headline, explanation) given the matched callee.
    pub message: fn(&str) -> (String, String),
    /// Remediation guidance (returned as the [`Remediation`] body).
    pub remediation: &'static str,
    /// Optional sink-arg predicate. When `Some`, called per matched
    /// sink with the call's source range; if it returns `false` the
    /// sink is skipped silently.
    pub sink_arg_check: Option<SinkArgCheck>,
    /// Whether to seed function parameters as tainted. Web-handler
    /// rules (xss, sqli, ssrf, command_injection,
    /// unsafe_deserialization) want this on so axum/Express extractors
    /// flow through. R-05 (repr_on_untrusted) and path_traversal
    /// disable it to avoid flagging every internal helper that takes
    /// a `&Edge` / `&Path` / `&Error` by reference — those parameters
    /// are not "untrusted" in any useful sense.
    pub seed_parameters: bool,
}

/// Run a per-rule scan with the standard Phase-3 dataflow scaffold.
///
/// Steps: enumerate every Function/Method, build its tainted-set,
/// walk every descendant Call whose callee matches `spec.sinks`, and
/// emit a finding when any argument identifier sits in the set or
/// when a source call is nested directly inside the sink.
pub(crate) fn run_taint_rule(
    ctx: &cc_rules::RuleContext<'_>,
    spec: &TaintRuleSpec,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for fn_id in function_node_ids(ctx.batch) {
        let tainted = build_tainted_set(ctx.batch, fn_id, spec.sources, spec.seed_parameters);
        emit_for_function(ctx, fn_id, &tainted, spec, &mut out);
    }
    out
}

fn emit_for_function(
    ctx: &cc_rules::RuleContext<'_>,
    fn_id: NodeId,
    tainted: &TaintedSet,
    spec: &TaintRuleSpec,
    out: &mut Vec<Finding>,
) {
    let batch = ctx.batch;
    for desc in collect_descendants_in_order(batch, fn_id) {
        let Some(callee) = string_prop(batch, desc, "callee_ref") else {
            continue;
        };
        if !callee_matches(callee, spec.sinks) {
            continue;
        }
        if !call_has_tainted_arg(batch, desc, tainted, spec.sources) {
            continue;
        }
        if let Some(f) = emit_finding(ctx, desc, callee, spec) {
            out.push(f);
        }
    }
}

fn emit_finding(
    ctx: &cc_rules::RuleContext<'_>,
    call: NodeId,
    callee: &str,
    spec: &TaintRuleSpec,
) -> Option<Finding> {
    let batch = ctx.batch;
    let path = enclosing_file_path(batch, call)?;
    if is_test_file_path(&path) {
        return None;
    }
    if let Some(check) = spec.sink_arg_check {
        if !check(batch, ctx.source, &path, call, callee) {
            return None;
        }
    }
    let (headline, explanation) = (spec.message)(callee);
    let location = location_from_node(batch, call, path);
    Some(build_finding(TaintFindingBlueprint {
        rule_id: spec.rule_id,
        category: Category::Taint,
        severity: Severity::Blocker,
        confidence: Confidence::new(spec.confidence),
        location,
        headline,
        explanation,
        remediation: Remediation::SuggestedRewrite(spec.remediation.into()),
        snippet: callee.to_owned(),
        weight: spec.weight,
    }))
}

/// True iff `path` is a source file inside a rule-pack crate
/// (`crates/cc-rules-*/src/...`). Probes that scan source text for their
/// own detector needles skip these to avoid rule-on-rule noise.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

/// True iff `path` looks like a test file. Matches the heuristic used
/// by Family-19 so taint findings in tests/ are silently dropped.
#[must_use]
pub(crate) fn is_test_file_path(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
    if lower.contains("/tests/")
        || lower.contains("/test/")
        || lower.contains("/__tests__/")
        || lower.starts_with("tests/")
        || lower.starts_with("test/")
    {
        return true;
    }
    match path.file_stem() {
        Some(stem) => is_test_stem(&stem.to_ascii_lowercase()),
        None => false,
    }
}

fn is_test_stem(stem_lower: &str) -> bool {
    stem_lower == "tests"
        || stem_lower == "test"
        || stem_lower.starts_with("test_")
        || stem_lower.ends_with("_test")
        || stem_lower.ends_with(".test")
        || stem_lower.ends_with(".spec")
}
