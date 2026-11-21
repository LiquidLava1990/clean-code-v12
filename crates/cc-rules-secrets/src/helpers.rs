//! Internal helpers shared across Family-19 probes.
//!
//! This is Family-19's analogue of `cc-rules-tier0::helpers`. Rather
//! than depend on the Tier-0 crate, the few primitives we need are
//! re-implemented here so the two packs stay independent.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, nodes_of_kind, range_prop, string_prop};
use cc_rules::RuleContext;

use crate::pack::BuiltinSecretsPack;

/// Iterate every `(file_path, bytes)` pair the current batch + source
/// table can supply, applying the standard skip filters used by every
/// Phase-8 source-text probe (test files, rule-pack sources, fixtures).
///
/// Each tuple yields an owned [`Utf8PathBuf`] (so callers can build
/// findings without re-borrowing the batch) and the `&'static [u8]`
/// slice straight from the [`cc_rules::SourceTable`].
pub(crate) fn iter_scannable_files<'a>(
    ctx: &'a RuleContext<'_>,
) -> impl Iterator<Item = (Utf8PathBuf, &'static [u8])> + 'a {
    nodes_of_kind(ctx.batch, NodeKind::File).filter_map(move |node| {
        let raw = string_prop(ctx.batch, node.id, "path")?;
        let path = Utf8PathBuf::from(raw);
        if is_test_file_path(&path) || looks_like_rule_pack_source(&path) || is_fixture_path(&path)
        {
            return None;
        }
        let bytes = ctx.source.get(path.as_path());
        if bytes.is_empty() {
            return None;
        }
        Some((path, bytes))
    })
}

/// Build a [`Location`] anchored at a byte offset inside the file. The
/// offset is converted to (line, column) with a single linear scan.
#[must_use]
pub(crate) fn location_for_offset(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Location {
    let (line, col) = line_col_for_offset(bytes, offset);
    let pos = Position::new(line, col, u32::try_from(offset).unwrap_or(u32::MAX));
    Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    }
}

/// Convert a byte offset into a 1-based `(line, column)` pair. Lines
/// split on `\n`; column counts bytes since the previous newline.
#[must_use]
fn line_col_for_offset(bytes: &[u8], offset: usize) -> (u32, u32) {
    let cap = offset.min(bytes.len());
    let mut line: u32 = 1;
    let mut col: u32 = 1;
    for &b in &bytes[..cap] {
        if b == b'\n' {
            line = line.saturating_add(1);
            col = 1;
        } else {
            col = col.saturating_add(1);
        }
    }
    (line, col)
}

/// Return up to `max_len` bytes around `offset` as a printable snippet,
/// trimming non-UTF-8 boundaries. Used as the evidence snippet for
/// source-byte probes.
#[must_use]
pub(crate) fn snippet_around(bytes: &[u8], offset: usize, max_len: usize) -> String {
    let lo = offset.min(bytes.len());
    let hi = (offset + max_len).min(bytes.len());
    String::from_utf8_lossy(&bytes[lo..hi]).into_owned()
}

/// Probe-pack identity stamped on every Family-19 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinSecretsPack::PACK_ID,
        BuiltinSecretsPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the AST_PARENT chain up to the enclosing [`NodeKind::File`] and
/// return the file's `path` property.
#[must_use]
pub(crate) fn enclosing_file_path(batch: &CpgWriteBatch, mut id: NodeId) -> Option<Utf8PathBuf> {
    for _ in 0..256_u16 {
        if let Some(node) = cc_frontend::query::node_by_id(batch, id) {
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

/// Build a [`Location`] anchored at the start of `path` — used when no
/// node range is available (e.g. dotenv whole-file findings).
#[must_use]
pub(crate) fn location_for_file(file: Utf8PathBuf, line: u32) -> Location {
    let pos = Position::new(line.max(1), 1, 0);
    Location {
        file,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    }
}

/// True iff `path` looks like a test file across the four supported
/// languages. Re-implemented from the Tier-0 helper rather than
/// depending on `cc-rules-tier0` so the packs remain siblings.
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

/// True iff `path` is a source file inside a rule-pack crate
/// (`crates/cc-rules-*/src/...`). Probes that scan source text for their
/// own detector needles skip these so a regex pattern embedded inside a
/// probe definition does not flag the probe itself.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

/// True iff `path` has a `.md` or `.txt` extension — used by some
/// secret probes that want to skip prose-only files even outside of a
/// fixture directory.
#[must_use]
pub(crate) fn is_doc_extension(path: &Utf8PathBuf) -> bool {
    matches!(
        path.extension().map(str::to_ascii_lowercase).as_deref(),
        Some("md") | Some("txt")
    )
}

/// True iff `path` lives under a fixture directory (`corpus/`,
/// `tests/fixtures/`, `**/test-fixtures/**`, `**/fixtures/**`). Phase-8
/// secret probes skip fixtures so canonical example tokens do not fire.
#[must_use]
pub(crate) fn is_fixture_path(path: &Utf8PathBuf) -> bool {
    let lower = path.as_str().replace('\\', "/").to_ascii_lowercase();
    lower.starts_with("corpus/")
        || lower.contains("/corpus/")
        || lower.contains("/tests/fixtures/")
        || lower.starts_with("tests/fixtures/")
        || lower.contains("/test-fixtures/")
        || lower.contains("/fixtures/")
}

/// Inputs every Family-19 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct SecretsFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.config.secret_in_code"`.
    pub rule_id: &'static str,
    /// Top-level category bucket the rule belongs to.
    pub category: Category,
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

/// Build a complete [`Finding`] from a [`SecretsFindingBlueprint`].
pub(crate) fn build_finding(blueprint: SecretsFindingBlueprint) -> Finding {
    let SecretsFindingBlueprint {
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
        .expect("Family-19 finding builder receives all required fields")
}

/// Shannon entropy (bits per char) of `s`. Empty strings score 0.
///
/// Used to decide whether a generic string literal assigned to a
/// `*_key` / `*_secret` / `*_token` / `*_password` variable is likely
/// to be a real secret. ~3.5 bits/char is the conventional threshold;
/// see [`MIN_ENTROPY_BITS`].
#[must_use]
pub(crate) fn entropy_score(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for byte in s.bytes() {
        counts[byte as usize] = counts[byte as usize].saturating_add(1);
        total = total.saturating_add(1);
    }
    let total_f = f64::from(total);
    let mut h = 0.0_f64;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / total_f;
        h -= p * p.log2();
    }
    h
}

/// Minimum Shannon entropy (bits/char) before a generic string literal
/// is treated as a candidate secret.
pub(crate) const MIN_ENTROPY_BITS: f64 = 3.5;

/// Minimum length (chars) before a generic high-entropy string is
/// treated as a candidate secret.
pub(crate) const MIN_GENERIC_LEN: usize = 32;

/// Discriminant for the secret-pattern table — which detector fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretKind {
    /// `AKIA…` / `ASIA…`.
    AwsKey,
    /// `ghp_…` / `gho_…` / `ghu_…` / `ghs_…` / `ghr_…`.
    GithubToken,
    /// `xoxa-…` / `xoxb-…` / `xoxp-…` / `xoxr-…` / `xoxs-…`.
    SlackToken,
    /// `sk_live_…` / `pk_live_…`.
    StripeKey,
    /// `eyJ…` JWT.
    Jwt,
    /// `-----BEGIN … PRIVATE KEY-----` PEM header.
    PrivateKey,
    /// Generic high-entropy literal assigned to a `*_key`-style name.
    Generic,
}

impl SecretKind {
    /// Human label for headlines.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AwsKey => "AWS access key",
            Self::GithubToken => "GitHub personal access token",
            Self::SlackToken => "Slack token",
            Self::StripeKey => "Stripe API key",
            Self::Jwt => "JWT",
            Self::PrivateKey => "private-key PEM header",
            Self::Generic => "high-entropy secret-shaped literal",
        }
    }
}

/// Match `s` against every known vendor pattern. Returns the first hit
/// or `None`. Implementation is deliberately byte-by-byte rather than
/// regex-based so the crate has zero extra dependencies.
#[must_use]
pub(crate) fn match_known_secret(s: &str) -> Option<SecretKind> {
    if matches_aws(s) {
        return Some(SecretKind::AwsKey);
    }
    if matches_github(s) {
        return Some(SecretKind::GithubToken);
    }
    if matches_slack(s) {
        return Some(SecretKind::SlackToken);
    }
    if matches_stripe(s) {
        return Some(SecretKind::StripeKey);
    }
    if matches_jwt(s) {
        return Some(SecretKind::Jwt);
    }
    if matches_private_key_header(s) {
        return Some(SecretKind::PrivateKey);
    }
    None
}

fn matches_aws(s: &str) -> bool {
    if s.len() != 20 {
        return false;
    }
    let prefix_ok = s.starts_with("AKIA") || s.starts_with("ASIA");
    if !prefix_ok {
        return false;
    }
    s.bytes()
        .skip(4)
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn matches_github(s: &str) -> bool {
    let prefixes = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"];
    let Some(prefix) = prefixes.iter().find(|p| s.starts_with(*p)) else {
        return false;
    };
    let body = &s[prefix.len()..];
    body.len() >= 36 && body.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn matches_slack(s: &str) -> bool {
    if !s.starts_with("xox") || s.len() < 15 {
        return false;
    }
    let bytes = s.as_bytes();
    let kind_byte = bytes.get(3).copied().unwrap_or(b' ');
    if !matches!(kind_byte, b'a' | b'b' | b'p' | b'r' | b's') {
        return false;
    }
    if bytes.get(4) != Some(&b'-') {
        return false;
    }
    s[5..]
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn matches_stripe(s: &str) -> bool {
    let stripped = s
        .strip_prefix("sk_live_")
        .or_else(|| s.strip_prefix("pk_live_"));
    let Some(body) = stripped else {
        return false;
    };
    body.len() >= 24 && body.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn matches_jwt(s: &str) -> bool {
    if !s.starts_with("eyJ") {
        return false;
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts[1].starts_with("eyJ")
        && all_b64url(parts[0])
        && all_b64url(parts[1])
        && all_b64url(parts[2])
}

fn all_b64url(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'=')
}

fn matches_private_key_header(s: &str) -> bool {
    s.contains("-----BEGIN ") && s.contains("PRIVATE KEY-----")
}

/// True iff `var_name` looks like a credential-bearing identifier.
/// Used by the generic-entropy branch of `secret_in_code`.
#[must_use]
pub(crate) fn looks_like_credential_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("_key")
        || lower.ends_with("_secret")
        || lower.ends_with("_token")
        || lower.ends_with("_password")
        || lower == "api_key"
        || lower == "auth_token"
        || lower == "secret"
        || lower == "password"
}
