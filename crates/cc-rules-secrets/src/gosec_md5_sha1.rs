//! `cc.config.gosec_md5_sha1` — Go `crypto/md5` / `crypto/sha1` use for
//! non-checksum (security) purposes.
//!
//! Mirrors [gosec G401] (`Detect the usage of MD5 or SHA1`) and
//! [gosec G405] (`Use of weak crypto primitive`). The existing
//! `cc.config.weak_crypto` probe catches AST-level call nodes; this
//! probe is a Go-only source-byte detector that fires only when a
//! security keyword (password / signature / auth / token / crypto)
//! appears within the same function body.
//!
//! [gosec G401]: https://github.com/securego/gosec/blob/master/rules/weakcrypto.go

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const PATTERNS: &[&[u8]] = &[b"md5.New(", b"md5.Sum(", b"sha1.New(", b"sha1.Sum("];
const SECURITY_HINTS: &[&[u8]] = &[
    b"password",
    b"signature",
    b"signing",
    b"auth",
    b"token",
    b"crypto",
    b"hmac",
    b"digest_for_auth",
];
const HINT_RADIUS_BYTES: usize = 320;

/// Family-19 probe R-GOSEC-MD5-SHA1.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecMd5Sha1Rule;

impl Rule for GosecMd5Sha1Rule {
    fn rule_id(&self) -> &'static str {
        "cc.config.gosec_md5_sha1"
    }
    fn category(&self) -> Category {
        Category::Config
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Go md5/sha1 used for security purposes (gosec G401/G405)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if !is_go_source(&path) {
                continue;
            }
            for offset in find_weak_hash_calls(bytes) {
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

fn find_weak_hash_calls(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    for pat in PATTERNS {
        let mut i = 0;
        while i + pat.len() <= bytes.len() {
            if &bytes[i..i + pat.len()] == *pat
                && left_word_boundary(bytes, i)
                && has_security_keyword_nearby(bytes, i)
            {
                hits.push(i);
                i += pat.len();
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

fn has_security_keyword_nearby(bytes: &[u8], call_offset: usize) -> bool {
    let lo = call_offset.saturating_sub(HINT_RADIUS_BYTES);
    let hi = (call_offset + HINT_RADIUS_BYTES).min(bytes.len());
    let window: Vec<u8> = bytes[lo..hi].iter().map(u8::to_ascii_lowercase).collect();
    let stripped = strip_crypto_imports(&window);
    SECURITY_HINTS.iter().any(|h| slice_contains(&stripped, h))
}

/// Replace `"crypto/md5"` / `"crypto/sha1"` / `"crypto/hmac"` import
/// strings with spaces of equal length so the "crypto" hint does not
/// fire on the import line alone.
fn strip_crypto_imports(window: &[u8]) -> Vec<u8> {
    let mut out = window.to_vec();
    for needle in [
        b"\"crypto/md5\"".as_slice(),
        b"\"crypto/sha1\"".as_slice(),
        b"\"crypto/hmac\"".as_slice(),
        b"\"crypto/aes\"".as_slice(),
    ] {
        replace_with_spaces(&mut out, needle);
    }
    out
}

fn replace_with_spaces(buf: &mut [u8], needle: &[u8]) {
    if needle.is_empty() || needle.len() > buf.len() {
        return;
    }
    let mut i = 0;
    while i + needle.len() <= buf.len() {
        if &buf[i..i + needle.len()] == needle {
            for j in i..i + needle.len() {
                buf[j] = b' ';
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
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
        rule_id: "cc.config.gosec_md5_sha1",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: "Go md5/sha1 used for security purpose (gosec G401/G405)".into(),
        explanation: "`crypto/md5` and `crypto/sha1` are cryptographically \
             broken: collisions are practical and HMAC-MD5/HMAC-SHA1 \
             constructions are deprecated. gosec G401 / G405 flags the \
             same shape. Using either for password hashing, signature \
             verification, or auth-token derivation is a real \
             correctness bug."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Switch to `crypto/sha256`, `crypto/sha512`, or BLAKE2/3 for \
             integrity. For password hashing use `golang.org/x/crypto/\
             argon2` or `bcrypt`. For HMAC, use `crypto/hmac` over \
             SHA-256 / SHA-512."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
