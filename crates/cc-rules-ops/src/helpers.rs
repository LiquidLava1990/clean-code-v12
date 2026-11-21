//! Internal helpers shared across Family-12 (operations) probes.
//!
//! Re-implements the small set of traversal primitives every Family-12
//! rule needs so the pack stays sibling-independent of `cc-rules-tier0`,
//! `cc-rules-bugs`, `cc-rules-completeness`, and any concurrent Phase-4
//! pack.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinOpsPack;

// ---------- callee tables -------------------------------------------------

/// HTTP / RPC client constructors + verbs across the four supported
/// languages. Substring-matched against the same callee slots
/// `cc-rules-bugs::callee_text` walks (`callee_ref`, `name`,
/// `signature`, `qualified`, `callee`).
pub(crate) const HTTP_CLIENT_CALLEES: &[&str] = &[
    // Python
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.request",
    "urllib.request.urlopen",
    "urllib.urlopen",
    "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post",
    // JS / TS
    "axios.get",
    "axios.post",
    "axios.put",
    "axios.delete",
    "axios.request",
    "fetch(",
    // Rust
    "reqwest::get",
    "reqwest::Client::new",
    "reqwest::Client::get",
    "reqwest::Client::post",
    "ureq::get",
    "ureq::post",
    // Go
    "http.Get",
    "http.Post",
    "http.NewRequest",
    "http.Do",
];

/// DB / RPC / queue clients that benefit from circuit breakers.
pub(crate) const DB_CLIENT_CALLEES: &[&str] = &[
    "psycopg2.connect",
    "asyncpg.connect",
    "pymongo.MongoClient",
    "redis.Redis",
    "redis::Client::open",
    "sqlx::PgPool::connect",
    "kafka",
    "rabbit",
    "grpc.",
    "tonic::",
    "rpc.",
];

/// Retry-library callees that imply backoff configuration is at least
/// possible — presence does not guarantee correct config, but absence
/// inside a retry loop is a confident signal.
pub(crate) const RETRY_LIB_CALLEES: &[&str] = &[
    "tenacity",
    "backoff",
    "retrying",
    "retry::",
    "tokio_retry::",
    "p_retry",
    "polly",
    "Retry::new",
    "ExponentialBackoff",
    "exponential_backoff",
];

/// Circuit-breaker library callees. Substring-matched against the same
/// callee slots; presence anywhere in the enclosing function body
/// silences `no_circuit_breaker`.
pub(crate) const BREAKER_LIB_CALLEES: &[&str] = &[
    "CircuitBreaker",
    "circuit_breaker",
    "failsafe",
    "tower::ServiceBuilder::circuit_breaker",
    "polly",
    "hystrix",
    "resilience4j",
    "pybreaker",
    "opossum",
];

/// Rate-limit library callees. Same matching strategy as the breaker
/// table; presence silences `no_rate_limit`.
pub(crate) const RATE_LIMIT_LIB_CALLEES: &[&str] = &[
    "RateLimiter::new",
    "RateLimiter",
    "governor::RateLimiter",
    "governor::",
    "bottleneck",
    "ratelimit",
    "rate_limit",
    "tower::limit::RateLimitLayer",
    "leaky_bucket",
    "token_bucket",
];

/// Unbounded-queue constructors. Each entry is the canonical lexical
/// form a frontend lifts into the callee text. Bounded variants
/// (`Queue(maxsize=N)` / `mpsc::channel(N)` / `make(chan T, N)`) share
/// no constructor name with these and so escape the match.
pub(crate) const QUEUE_CONSTRUCTOR_CALLEES: &[&str] = &[
    "queue.Queue(",
    "queue.SimpleQueue(",
    "asyncio.Queue(",
    "multiprocessing.Queue(",
    "crossbeam::channel::unbounded",
    "tokio::sync::mpsc::unbounded_channel",
    "mpsc::unbounded_channel",
    "futures::channel::mpsc::unbounded",
    "std::sync::mpsc::channel",
];

// ---------- finding plumbing ---------------------------------------------

/// Probe-pack identity stamped on every Family-12 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinOpsPack::PACK_ID,
        BuiltinOpsPack::PACK_SEMVER,
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

/// Best-effort positional-argument text for a [`NodeKind::Call`] node.
#[must_use]
pub(crate) fn call_args_text(batch: &CpgWriteBatch, id: NodeId) -> String {
    let mut buf = String::new();
    for key in ["args", "arg0", "first_arg", "kwargs"] {
        if let Some(value) = string_prop(batch, id, key) {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(value);
        }
    }
    buf
}

/// True iff `text` matches any needle in `table` as a substring.
#[must_use]
pub(crate) fn matches_any(text: &str, table: &[&str]) -> bool {
    table.iter().any(|n| text.contains(n))
}

// ---------- blueprint -----------------------------------------------------

/// Inputs every Family-12 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct OpsFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.ops.missing_timeout"`.
    pub rule_id: &'static str,
    /// Severity to stamp on the finding.
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

/// Build a complete [`Finding`] from an [`OpsFindingBlueprint`].
pub(crate) fn build_finding(blueprint: OpsFindingBlueprint) -> Finding {
    let OpsFindingBlueprint {
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
        .category(Category::Ops)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-12 finding builder receives all required fields")
}
