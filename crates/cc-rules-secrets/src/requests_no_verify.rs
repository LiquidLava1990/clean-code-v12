//! `cc.config.requests_no_verify` — flag Python `requests.<verb>(…,
//! verify=False)` calls. Mirrors [Bandit B501] (`request_with_no_cert_validation`).
//!
//! TLS verification disabled in `requests` strips authentication of
//! the server identity entirely — any active network attacker can MITM
//! the connection and the client will accept the response. Test
//! environments often justify this temporarily, but the surrounding
//! code rarely re-enables it on production deployments.
//!
//! Detection: source-byte scan for `\.<verb>(...verify=False...)`
//! across `.py` files. AST-grade detection would need full Python
//! call-arg lifting; the byte scan is the safe Phase-8 floor.
//!
//! [Bandit B501]: https://bandit.readthedocs.io/en/latest/plugins/b501_request_with_no_cert_validation.html

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const VERBS: &[&[u8]] = &[
    b"get", b"post", b"put", b"patch", b"delete", b"head", b"options", b"request",
];
const KW_NEEDLE: &[u8] = b"verify=False";
const SCAN_WINDOW: usize = 512;

/// Family-19 probe R-REQUESTS-NO-VERIFY.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestsNoVerifyRule;

impl Rule for RequestsNoVerifyRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.requests_no_verify"
    }
    fn category(&self) -> Category {
        Category::Config
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "Python requests call with verify=False disables TLS host verification"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if !is_python_path(&path) {
                continue;
            }
            for offset in find_unsafe_calls(bytes) {
                out.push(emit(path.clone(), bytes, offset));
            }
        }
        out
    }
}

fn is_python_path(path: &Utf8PathBuf) -> bool {
    matches!(
        path.extension().map(str::to_ascii_lowercase).as_deref(),
        Some("py")
    )
}

/// Walk `bytes` looking for `.<verb>(` followed (within a 512-byte
/// scan window) by `verify=False`. The window cap prevents matching
/// the keyword from a different unrelated call further down the file.
fn find_unsafe_calls(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    for verb in VERBS {
        find_verb_hits(bytes, verb, &mut hits);
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

fn find_verb_hits(bytes: &[u8], verb: &[u8], out: &mut Vec<usize>) {
    let mut i = 0;
    while i + verb.len() + 1 < bytes.len() {
        if matches_verb_call(bytes, i, verb) {
            let after = i + verb.len() + 1;
            if window_has_kw(bytes, after, KW_NEEDLE) {
                out.push(i);
            }
        }
        i += 1;
    }
}

/// True iff `bytes[i..]` is `.verb(` with a leading word-boundary so
/// a method-suffix collision (e.g. `.bigget(` vs `.get(`) is avoided.
fn matches_verb_call(bytes: &[u8], i: usize, verb: &[u8]) -> bool {
    if bytes.get(i) != Some(&b'.') {
        return false;
    }
    let body_start = i + 1;
    let body_end = body_start + verb.len();
    if body_end >= bytes.len() {
        return false;
    }
    if &bytes[body_start..body_end] != verb {
        return false;
    }
    bytes.get(body_end) == Some(&b'(')
}

/// True iff `needle` appears within the next [`SCAN_WINDOW`] bytes.
/// Stops at a closing `)` at depth 0 to avoid leaking into a follow-up
/// statement.
fn window_has_kw(bytes: &[u8], start: usize, needle: &[u8]) -> bool {
    let cap = (start + SCAN_WINDOW).min(bytes.len());
    let mut depth = 1i32;
    let mut j = start;
    while j < cap {
        match bytes[j] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return slice_contains(&bytes[start..j], needle);
                }
            }
            _ => {}
        }
        j += 1;
    }
    slice_contains(&bytes[start..cap], needle)
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
        rule_id: "cc.config.requests_no_verify",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "`requests` call disables TLS host verification (`verify=False`)".into(),
        explanation: "`requests.<verb>(..., verify=False)` accepts any \
             certificate the server presents, including one signed by a \
             local attacker's CA. Bandit B501 catches the same pattern. \
             In production this is equivalent to running plaintext."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Drop `verify=False`. If the target really uses a private CA, \
             pass `verify=\"/path/to/ca-bundle.pem\"` (or the env-driven \
             `REQUESTS_CA_BUNDLE`). Tests should hit a fixture server \
             with a known cert, not bypass verification."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
