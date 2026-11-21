//! `cc.config.gosec_weak_random` — Go `math/rand` use for
//! security-sensitive purposes (token, password, salt, nonce, key).
//!
//! Mirrors [gosec G404] (`Use of weak random number generator`). The
//! `math/rand` package is deterministic given the seed; for any
//! security-grade randomness `crypto/rand` is the only correct choice.
//!
//! Detection: source-byte scan for `rand.Int(`, `rand.Read(`,
//! `rand.Intn(`, `rand.Int63(`, `rand.Int31(`, `rand.Float64(`, etc.
//! within 3 lines of a security-keyword (token / password / salt /
//! nonce / key / secret / iv) on the same file.
//!
//! [gosec G404]: https://github.com/securego/gosec/blob/master/rules/rand.go

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const RAND_FNS: &[&[u8]] = &[
    b"rand.Int(",
    b"rand.Intn(",
    b"rand.Int31(",
    b"rand.Int31n(",
    b"rand.Int63(",
    b"rand.Int63n(",
    b"rand.Read(",
    b"rand.Float32(",
    b"rand.Float64(",
    b"rand.Uint32(",
    b"rand.Uint64(",
];
const SECURITY_HINTS: &[&[u8]] = &[
    b"token",
    b"password",
    b"passwd",
    b"salt",
    b"nonce",
    b"key",
    b"secret",
    b"iv",
    b"session",
    b"auth",
];
const HINT_RADIUS_BYTES: usize = 256;

/// Family-19 probe R-GOSEC-WEAK-RANDOM.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecWeakRandomRule;

impl Rule for GosecWeakRandomRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.gosec_weak_random"
    }
    fn category(&self) -> Category {
        Category::Config
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Go math/rand use for security-sensitive randomness (gosec G404)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if !is_go_source(&path) {
                continue;
            }
            if uses_crypto_rand_only(bytes) {
                continue;
            }
            for offset in find_weak_random_calls(bytes) {
                out.push(emit(path.clone(), bytes, offset));
            }
        }
        out
    }
}

fn is_go_source(path: &Utf8PathBuf) -> bool {
    let ext_ok = matches!(
        path.extension().map(str::to_ascii_lowercase).as_deref(),
        Some("go")
    );
    if !ext_ok {
        return false;
    }
    !path
        .file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_test.go"))
}

/// True iff the file imports only `crypto/rand` (renamed to `rand`)
/// and never the weak `math/rand` package. Lets us suppress findings
/// when the user already did the right thing.
fn uses_crypto_rand_only(bytes: &[u8]) -> bool {
    let imports_math = slice_contains(bytes, b"\"math/rand\"");
    !imports_math
}

fn find_weak_random_calls(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    for fn_pat in RAND_FNS {
        let mut i = 0;
        while i + fn_pat.len() <= bytes.len() {
            if &bytes[i..i + fn_pat.len()] == *fn_pat
                && left_word_boundary(bytes, i)
                && near_security_hint(bytes, i)
            {
                hits.push(i);
                i += fn_pat.len();
            } else {
                i += 1;
            }
        }
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

fn left_word_boundary(bytes: &[u8], i: usize) -> bool {
    if i == 0 {
        return true;
    }
    let prev = bytes[i - 1];
    !prev.is_ascii_alphanumeric() && prev != b'_' && prev != b'/'
}

/// True iff a security keyword appears within [`HINT_RADIUS_BYTES`] of
/// the call site (case-insensitive).
fn near_security_hint(bytes: &[u8], call_offset: usize) -> bool {
    let lo = call_offset.saturating_sub(HINT_RADIUS_BYTES);
    let hi = (call_offset + HINT_RADIUS_BYTES).min(bytes.len());
    let window: Vec<u8> = bytes[lo..hi].iter().map(u8::to_ascii_lowercase).collect();
    SECURITY_HINTS.iter().any(|h| slice_contains(&window, h))
}

fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, 96);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.gosec_weak_random",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "Go `math/rand` used for security-sensitive randomness (gosec G404)".into(),
        explanation: "`math/rand` is deterministic given its seed and is \
             unsuitable for tokens, passwords, salts, nonces, keys, or \
             session ids. gosec G404 flags this exact pattern. An attacker \
             who learns the seed (or one piece of output) can reproduce \
             the entire stream."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Use `crypto/rand` instead: `rand.Read(buf)` from \
             `crypto/rand` returns OS-grade entropy and never reuses \
             output across processes."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
