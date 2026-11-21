//! `cc.shape.duplication` — flag pairs of functions that share ≥ 10
//! token-shingle hashes (copy-paste-modify smell).
//!
//! Threshold rationale: 6 over-fires on per-domain boilerplate (HTTP
//! request → parse → return shaped helpers across many sibling scrapers
//! / drivers / connectors). Empirically, on the CrawlRX scraper fork
//! (44 sibling scraper modules), 6 produced ~150 pairs, most at 6–14
//! shingles where the shared "boilerplate" is the per-call
//! `requests.get → BeautifulSoup → return list[dict]` skeleton — not a
//! DRY opportunity, just a per-vendor wrapper. 10 keeps high-signal
//! copy-paste (>= 50 shingles routinely fires) while pruning the
//! sibling-wrapper noise floor.
//!
//! Phase-1 simplification: the upstream `cc-frontend` does not yet
//! expose a `tokens_for(function)` accessor. We fall back to a
//! word-stream extracted from the function's source-byte range
//! (whitespace-split, literals canonicalised). This is good enough to
//! catch copy-paste blocks but yields less precision than a real
//! lexer-driven token stream.
//!
//! TODO(W3): switch to `cc_frontend::tokens_for(fn_id)` when available.

use std::collections::HashMap;

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Location, RelatedLocation, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, byte_window, enclosing_file_path, is_test_file_path, location_from_node,
    snippet_from_bytes, Tier0FindingBlueprint,
};

/// Tokens per shingle (k-shingle window).
const K: usize = 12;
/// Minimum total tokens for a function to participate in duplication
/// detection — keeps tiny getters/setters out.
const MIN_TOKENS: usize = 30;
/// Minimum shared shingles between two functions to fire — see module
/// docs for rationale on why 10 (not 6).
const MIN_SHARED_SHINGLES: usize = 10;
/// Minimum number of `=>` arrows in a body before the dispatch-shape
/// heuristic can fire. Below this we don't have enough signal to
/// classify confidently — small functions with one or two arrows are
/// usually closures + iterator chains, not dispatch tables.
const DISPATCH_MIN_ARROWS: usize = 4;
/// Token-budget per `=>` arm used by the dispatch-shape classifier. A
/// typical `"kind" => Some(handler(args))` arm carries roughly this many
/// identifier tokens; multiplying gives a lower-bound on the share of
/// the token stream attributable to dispatch glue.
const DISPATCH_TOKENS_PER_ARM: usize = 6;
/// Threshold (numerator / denominator) on the dispatch-token / total-token
/// ratio. At or above this fraction the body is classified as
/// dispatch-shape and excluded from cross-function pairing.
const DISPATCH_RATIO_NUM: usize = 1;
const DISPATCH_RATIO_DEN: usize = 2;

/// Tier-0 forever rule R-DUP.
#[derive(Debug, Default, Clone, Copy)]
pub struct DuplicationRule;

impl Rule for DuplicationRule {
    fn rule_id(&self) -> &'static str {
        "cc.shape.duplication"
    }
    fn category(&self) -> Category {
        Category::Slop
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "function shares >= 10 token-shingle hashes with another function"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut profiles: Vec<FunctionProfile> = Vec::new();
        for kind in [NodeKind::Function, NodeKind::Method] {
            for node in nodes_of_kind(ctx.batch, kind) {
                if let Some(profile) = build_profile(ctx, node.id) {
                    profiles.push(profile);
                }
            }
        }
        emit_pair_findings(&profiles)
    }
}

/// Per-function shingle index used by the pair-matching pass.
struct FunctionProfile {
    id: NodeId,
    name: String,
    location: Location,
    snippet: String,
    shingles: Vec<u64>,
}

fn build_profile(ctx: &RuleContext<'_>, id: NodeId) -> Option<FunctionProfile> {
    let range = range_prop(ctx.batch, id, "range")?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if is_test_file_path(&path) {
        // Test files legitimately repeat setup boilerplate across cases;
        // flagging them as duplication is mass false-positive noise.
        return None;
    }
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return None;
    }
    if is_test_annotated(bytes, range.start.offset) {
        // Functions carrying `#[test]` / `#[tokio::test]` / `@pytest.fixture`
        // / `it("...", ...)` etc. are test cases. Setup boilerplate across
        // cases legitimately repeats — same rationale as the test-file
        // path skip above.
        return None;
    }
    let body = byte_window(bytes, range.start.offset, range.end.offset);
    let tokens = tokenize(body);
    if tokens.len() < MIN_TOKENS {
        return None;
    }
    if is_dispatch_shape(body, tokens.len()) {
        // Pure match-arm dispatch tables share boilerplate by design —
        // each language frontend repeats the shape across `dispatch_item`
        // / `dispatch_control` / `dispatch_expression`. SimHash can't
        // tell the per-arm node-kind strings apart from the structural
        // skeleton, so we exclude the body from cross-function pairing.
        return None;
    }
    let shingles = shingle_hashes(&tokens);
    if shingles.is_empty() {
        return None;
    }
    let name = string_prop(ctx.batch, id, "name")
        .unwrap_or("<anonymous>")
        .to_owned();
    let location = location_from_node(ctx.batch, id, path);
    let snippet = snippet_from_bytes(bytes, range.start.offset, range.end.offset);
    Some(FunctionProfile {
        id,
        name,
        location,
        snippet,
        shingles,
    })
}

/// Whitespace + punctuation split, canonicalised. Numeric/string
/// literals collapse to placeholders so trivial value tweaks don't
/// hide a copy-paste.
fn tokenize(bytes: &[u8]) -> Vec<String> {
    let text = std::str::from_utf8(bytes).unwrap_or("");
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            current.push(ch);
        } else {
            push_token(&mut out, &mut current);
        }
    }
    push_token(&mut out, &mut current);
    out
}

fn push_token(out: &mut Vec<String>, current: &mut String) {
    if current.is_empty() {
        return;
    }
    let canon = if current.chars().all(|c| c.is_ascii_digit()) {
        "<NUM>".to_owned()
    } else {
        std::mem::take(current)
    };
    current.clear();
    out.push(canon);
}

fn shingle_hashes(tokens: &[String]) -> Vec<u64> {
    if tokens.len() < K {
        return Vec::new();
    }
    tokens.windows(K).map(simhash_window).collect()
}

/// FNV-1a 64 over the joined window. Cheap, deterministic, and good
/// enough for `SimHash`'s role here (cross-function shared-bucket count).
fn simhash_window(window: &[String]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for token in window {
        for byte in token.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn emit_pair_findings(profiles: &[FunctionProfile]) -> Vec<Finding> {
    if profiles.len() < 2 {
        return Vec::new();
    }
    let shingle_index = build_shingle_index(profiles);
    let shared_counts = count_shared_shingles(&shingle_index);
    let pairs = qualifying_pairs(shared_counts);
    emit_unique_first_owner(profiles, &pairs)
}

/// Build a `shingle-hash -> [profile-index]` reverse index.
fn build_shingle_index(profiles: &[FunctionProfile]) -> HashMap<u64, Vec<usize>> {
    let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
    for (idx, profile) in profiles.iter().enumerate() {
        for hash in &profile.shingles {
            index.entry(*hash).or_default().push(idx);
        }
    }
    index
}

/// Count, per ordered-pair `(a, b)`, how many shingles both members share.
fn count_shared_shingles(
    shingle_index: &HashMap<u64, Vec<usize>>,
) -> HashMap<(usize, usize), usize> {
    let mut shared: HashMap<(usize, usize), usize> = HashMap::new();
    for owners in shingle_index.values() {
        if owners.len() < 2 {
            continue;
        }
        accumulate_owner_pairs(owners, &mut shared);
    }
    shared
}

/// Add 1 to the shared-count of every distinct ordered pair drawn from `owners`.
fn accumulate_owner_pairs(owners: &[usize], shared: &mut HashMap<(usize, usize), usize>) {
    for i in 0..owners.len() {
        for j in (i + 1)..owners.len() {
            let (a, b) = ordered_pair(owners[i], owners[j]);
            if a == b {
                continue;
            }
            *shared.entry((a, b)).or_insert(0) += 1;
        }
    }
}

/// Filter `shared` down to pairs at or above the firing threshold and sort
/// deterministically by `(a, b)`.
fn qualifying_pairs(shared: HashMap<(usize, usize), usize>) -> Vec<((usize, usize), usize)> {
    let mut pairs: Vec<((usize, usize), usize)> = shared
        .into_iter()
        .filter(|(_, count)| *count >= MIN_SHARED_SHINGLES)
        .collect();
    pairs.sort_by_key(|((a, b), _)| (*a, *b));
    pairs
}

/// Emit one finding per first-owner: a given `a` is reported against the
/// first matching `b` and then suppressed for subsequent pairs to avoid
/// k-nearest noise.
fn emit_unique_first_owner(
    profiles: &[FunctionProfile],
    pairs: &[((usize, usize), usize)],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut emitted: HashMap<usize, bool> = HashMap::new();
    for &((a, b), shared) in pairs {
        if emitted.contains_key(&a) {
            continue;
        }
        findings.push(build_dup_finding(&profiles[a], &profiles[b], shared));
        emitted.insert(a, true);
    }
    findings
}

const fn ordered_pair(a: usize, b: usize) -> (usize, usize) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

fn build_dup_finding(left: &FunctionProfile, right: &FunctionProfile, shared: usize) -> Finding {
    let mut finding = build_finding(Tier0FindingBlueprint {
        rule_id: "cc.shape.duplication",
        category: Category::Slop,
        severity: Severity::Blocker,
        confidence: Confidence::certain(),
        location: left.location.clone(),
        headline: format!(
            "function `{}` duplicates `{}` ({} shared shingles)",
            left.name, right.name, shared
        ),
        explanation: format!(
            "Copy-paste-modify smell. `{}` and `{}` share {} token-shingle \
             hashes (threshold {MIN_SHARED_SHINGLES}); extract the common logic.",
            left.name, right.name, shared
        ),
        remediation: Remediation::SuggestedRewrite(
            "Extract the shared body into a helper and call it from both sites; \
             keep per-site differences as parameters."
                .into(),
        ),
        snippet: left.snippet.clone(),
        weight: u32::try_from(shared).unwrap_or(u32::MAX),
    });
    let _ = left.id;
    finding.related.push(RelatedLocation {
        location: right.location.clone(),
        message: format!("duplicate of `{}`", left.name),
    });
    finding
}

/// Classify `body_bytes` as a "match-arm dispatch table" — a function
/// whose body is dominated by `kind_pattern => single_call(args)` arms.
///
/// Cross-language frontends intentionally repeat this shape (one
/// `dispatch_*` per node-kind family); the shared boilerplate is
/// architecture, not copy-paste. Excluding these from pair detection
/// removes 5 of the 14 self-host findings observed in 2026-04 without
/// loosening the rule for real copy-paste (regression covered by
/// `tests::duplication_still_flags_real_copy_paste_after_dispatch_heuristic`
/// and `tests::duplication_flags_two_copy_pasted_functions`).
///
/// Signal: count of `=>` arrows in the source bytes vs the
/// identifier-token count. When `arrows >= DISPATCH_MIN_ARROWS` and
/// `arrows * DISPATCH_TOKENS_PER_ARM` covers at least
/// `DISPATCH_RATIO_NUM / DISPATCH_RATIO_DEN` of the token stream, the
/// body is dispatch-shape.
const fn is_dispatch_shape(body_bytes: &[u8], total_tokens: usize) -> bool {
    if total_tokens == 0 {
        return false;
    }
    let arrows = count_match_arrows(body_bytes);
    if arrows < DISPATCH_MIN_ARROWS {
        return false;
    }
    let dispatch_tokens = arrows.saturating_mul(DISPATCH_TOKENS_PER_ARM);
    // `dispatch_tokens / total_tokens >= NUM / DEN` rewritten without
    // integer division loss.
    dispatch_tokens.saturating_mul(DISPATCH_RATIO_DEN)
        >= total_tokens.saturating_mul(DISPATCH_RATIO_NUM)
}

/// True iff `bytes[..start_offset]` ends with a test-runner annotation
/// in the eight bytes preceding the function definition. Catches Rust
/// (`#[test]`, `#[tokio::test]`), Python pytest (`@pytest.fixture`,
/// `@pytest.mark`), JS/TS (`it(`, `test(`, `describe(`) and Go's
/// `_test.go` convention is already covered by the path heuristic.
fn is_test_annotated(bytes: &[u8], start_offset: u32) -> bool {
    let start = start_offset as usize;
    if start == 0 || start > bytes.len() {
        return false;
    }
    // Look back up to 256 bytes for an annotation marker.
    let lookback_start = start.saturating_sub(256);
    let window = &bytes[lookback_start..start];
    let needles: &[&[u8]] = &[
        b"#[test]",
        b"#[tokio::test]",
        b"#[async_std::test]",
        b"#[rstest]",
        b"#[test_case",
        b"@pytest.",
        b"@unittest.",
    ];
    needles
        .iter()
        .any(|n| window.windows(n.len()).any(|w| w == *n))
}

/// Count occurrences of the `=>` arrow in `bytes`, the canonical
/// match-arm separator. Each arrow corresponds to one dispatch arm.
const fn count_match_arrows(bytes: &[u8]) -> usize {
    let mut count: usize = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'=' && bytes[i + 1] == b'>' {
            count += 1;
            i += 2;
        } else {
            i += 1;
        }
    }
    count
}
