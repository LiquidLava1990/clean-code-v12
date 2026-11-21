//! Internal helpers shared across Family-23 (anti-fragility) probes.
//!
//! Re-implements the small set of traversal primitives every Family-23
//! rule needs so the pack stays sibling-independent of `cc-rules-tier0`,
//! `cc-rules-bugs`, `cc-rules-taint`, and any concurrent Phase-4 pack.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinAntiFragilityPack;

/// Sleep / blocking-delay callees across the four supported languages.
///
/// Substring-matched against the same callee slots `cc-rules-bugs`
/// uses (`callee_ref`, `name`, `signature`, `qualified`, `callee`) so
/// frontends with different lift conventions all surface a hit.
pub(crate) const SLEEP_CALLEES: &[&str] = &[
    // Python
    "time.sleep",
    "asyncio.sleep",
    // Rust
    "std::thread::sleep",
    "thread::sleep",
    "tokio::time::sleep",
    "async_std::task::sleep",
    // Go
    "time.Sleep",
    // JS / TS
    "setTimeout",
    "setInterval",
];

/// Outbound-HTTP callees — same table as `cc-rules-taint::ssrf` SINKS,
/// minus the source-only `urllib.urlopen` aliases that don't carry a
/// URL arg in the same shape.
pub(crate) const HTTP_CALLEES: &[&str] = &[
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.urlopen",
    "httpx.get",
    "httpx.post",
    "aiohttp.ClientSession.get",
    "axios.get",
    "axios.post",
    "axios.request",
    "fetch",
    "http.get",
    "https.get",
    "http.request",
    "https.request",
    "reqwest::get",
    "reqwest::Client::get",
    "Client::get",
    "ureq::get",
    "http.Get",
    "http.Post",
    "http.NewRequest",
];

/// URL substrings that mark a request as test-local rather than
/// hitting a real external host.
pub(crate) const LOCALHOST_PATTERNS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "httptest.NewServer",
    "mockito",
    // mockito hands out `http://127.0.0.1:<port>/...` URLs at runtime;
    // its server constructor name is also a strong negative signal.
    "MockServer",
    "wiremock",
];

/// Probe-pack identity stamped on every Family-23 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinAntiFragilityPack::PACK_ID,
        BuiltinAntiFragilityPack::PACK_SEMVER,
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

/// True iff `path` looks like a test file across the four supported
/// languages. Re-implementation of the canonical detector — kept local
/// so this pack does not depend on `cc-rules-tier0`.
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

/// Best-effort URL-argument text for an outbound HTTP call.
///
/// Frontends typically lift the first positional argument as `arg0` /
/// `args` / `url`. Concatenating each slot gives the lexical haystack
/// the localhost detector matches against.
#[must_use]
pub(crate) fn call_url_text(batch: &CpgWriteBatch, id: NodeId) -> String {
    let mut buf = String::new();
    for key in ["url", "arg0", "args", "first_arg"] {
        if let Some(value) = string_prop(batch, id, key) {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(value);
        }
    }
    buf
}

/// True iff the lexical URL text resolves to a test-local target.
#[must_use]
pub(crate) fn looks_like_localhost(haystack: &str) -> bool {
    let lower = haystack.to_ascii_lowercase();
    LOCALHOST_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_ascii_lowercase()))
}

/// Inputs every Family-23 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct AntiFragilityFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.fragile.timing_assumption"`.
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

/// Build a complete [`Finding`] from an [`AntiFragilityFindingBlueprint`].
pub(crate) fn build_finding(blueprint: AntiFragilityFindingBlueprint) -> Finding {
    let AntiFragilityFindingBlueprint {
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
        .category(Category::Fragile)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-23 finding builder receives all required fields")
}
