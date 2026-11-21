//! Internal helpers shared across Family-11 (observability) probes.
//!
//! Re-implements the small set of traversal primitives every Family-11
//! rule needs so the pack stays sibling-independent of the other
//! Phase-4 packs.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinObservabilityPack;

/// Probe-pack identity stamped on every Family-11 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinObservabilityPack::PACK_ID,
        BuiltinObservabilityPack::PACK_SEMVER,
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

/// Walk the `AST_PARENT` chain to the nearest enclosing
/// [`NodeKind::Function`] or [`NodeKind::Method`]. Bounded to 256 hops.
#[must_use]
pub(crate) fn enclosing_function(batch: &CpgWriteBatch, mut id: NodeId) -> Option<NodeId> {
    for _ in 0..256_u16 {
        match node_kind(batch, id) {
            Some(NodeKind::Function | NodeKind::Method) => return Some(id),
            Some(_) => {}
            None => return None,
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

/// True iff `path` looks like a test file across the four supported
/// languages.
#[must_use]
pub(crate) fn is_test_file_path(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
    if has_test_segment(&lower) {
        return true;
    }
    match path.file_stem() {
        Some(stem) => is_test_stem(&stem.to_ascii_lowercase()),
        None => false,
    }
}

fn has_test_segment(lower: &str) -> bool {
    lower.contains("/tests/")
        || lower.contains("/test/")
        || lower.contains("/__tests__/")
        || lower.starts_with("tests/")
        || lower.starts_with("test/")
}

fn is_test_stem(stem_lower: &str) -> bool {
    stem_lower == "tests"
        || stem_lower == "test"
        || stem_lower.starts_with("test_")
        || stem_lower.ends_with("_test")
        || stem_lower.ends_with(".test")
        || stem_lower.ends_with(".spec")
}

/// True iff `path` is a source file inside a rule-pack crate.
/// Probes that scan source text for their own detector needles skip
/// these to avoid rule-on-rule noise.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
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

/// True iff `text` matches any callee needle in `needles` (substring).
#[must_use]
pub(crate) fn callee_matches(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| text.contains(n))
}

/// Canonical metric primitive callees across Rust, Python, Go, TS.
pub(crate) const METRIC_CALLEES: &[&str] = &[
    "prometheus::histogram",
    "prometheus::counter",
    "metrics::counter",
    "metrics::histogram",
    "metrics::gauge",
    "statsd.increment",
    "statsd.timing",
    "statsd.gauge",
    "prom_client.Counter",
    "prom_client.Histogram",
    "Histogram::with_label_values",
    "Counter::with_label_values",
    "tracing::info_span",
    "info_span!",
    ".observe(",
    ".inc(",
    ".set(",
    "MetricCounter",
    "histogram!(",
    "counter!(",
    "gauge!(",
];

/// Canonical structured-log + tracing macros.
pub(crate) const TRACING_CALLEES: &[&str] = &[
    "tracing::info",
    "tracing::warn",
    "tracing::error",
    "tracing::debug",
    "tracing::trace",
    "tracing::info_span",
    "tracing::span",
    "info_span!",
    "span!",
    "instrument",
    "with_context",
    "trace_async",
    "meta_async",
];

/// Canonical log-emit callees across the four supported languages.
pub(crate) const LOG_CALLEES: &[&str] = &[
    "log.error",
    "log.warning",
    "log.warn",
    "log.info",
    "log.debug",
    "logger.error",
    "logger.warning",
    "logger.warn",
    "logger.info",
    "logger.debug",
    "logging.error",
    "logging.warning",
    "logging.info",
    "logging.debug",
    "tracing::error",
    "tracing::warn",
    "tracing::info",
    "tracing::debug",
    "console.error",
    "console.warn",
    "console.info",
    "console.log",
    "slog::error",
    "slog::warn",
    "slog::info",
    "slog.Error",
    "slog.Warn",
    "slog.Info",
    "log.Error",
    "log.Print",
    "log.Println",
    "log.Printf",
];

/// Canonical outbound HTTP / RPC callees.
pub(crate) const HTTP_CALLEES: &[&str] = &[
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.request",
    "axios.get",
    "axios.post",
    "axios.put",
    "axios.delete",
    "axios.request",
    "fetch(",
    "reqwest::get",
    "reqwest::Client",
    "reqwest::blocking::get",
    "reqwest.Client",
    "http.Get",
    "http.Post",
    "http.Do",
    "http.NewRequest",
    "client.Do",
    "urlopen(",
    "urllib.request.urlopen",
];

/// External-I/O markers used by `missing_metrics` to identify a public
/// function as on a critical path. Captures DB / HTTP / file I/O.
pub(crate) const EXTERNAL_IO_CALLEES: &[&str] = &[
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "httpx.",
    "axios.",
    "fetch(",
    "reqwest::",
    "http.Get",
    "http.Post",
    "http.Do",
    "client.Do",
    "urlopen(",
    "psycopg2",
    "sqlalchemy",
    "session.execute",
    "session.query",
    "cursor.execute",
    "conn.execute",
    "db.execute",
    "db.Query",
    "db.QueryRow",
    "sqlx::query",
    "sqlx::Connection",
    "diesel::",
    "open(",
    "File::open",
    "fs::read",
    "fs::write",
    "io.ReadFile",
    "ioutil.ReadFile",
    "os.Open",
];

/// PII keywords matched against log format-string content.
pub(crate) const PII_KEYWORDS: &[&str] = &[
    "email",
    "ssn",
    "social_security",
    "phone",
    "address",
    "credit_card",
    "creditcard",
    "card_number",
    "cvv",
    "name",
    "first_name",
    "last_name",
    "full_name",
    "dob",
    "date_of_birth",
    "birthdate",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "token",
    "secret",
];

/// High-cardinality label keys that should never appear on a metric.
pub(crate) const HIGH_CARDINALITY_LABELS: &[&str] = &[
    "user_id",
    "userid",
    "user-id",
    "request_id",
    "requestid",
    "request-id",
    "session_id",
    "sessionid",
    "session-id",
    "email",
    "path",
    "url",
    "uri",
    "trace_id",
    "traceid",
];

/// Reasons a swallowed-exception handler is acceptable — a re-raise,
/// re-throw, or wrapping return.
pub(crate) const RERAISE_MARKERS: &[&str] = &[
    "raise",
    "throw",
    "return Err",
    "return err",
    "panic!",
    "anyhow::bail",
    "bail!",
    "Err(",
    "?;",
];

/// Inputs every Family-11 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct ObsFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.obs.silent_catch"`.
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

/// Build a complete [`Finding`] from an [`ObsFindingBlueprint`].
pub(crate) fn build_finding(blueprint: ObsFindingBlueprint) -> Finding {
    let ObsFindingBlueprint {
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
        .category(Category::Obs)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-11 finding builder receives all required fields")
}
