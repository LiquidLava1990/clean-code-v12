//! `cc.config.urllib_no_verify` — flag Python TLS-bypass patterns built
//! around `ssl` + `urllib`.
//!
//! Two source-byte shapes are recognised, both [Bandit B323]
//! (`request_with_no_cert_validation` / `unverified_context`):
//!
//! 1. `ssl._create_unverified_context()` (constructor or kwarg).
//! 2. `verify_mode = ssl.CERT_NONE` after building an `ssl.SSLContext`.
//!
//! Either pattern disables peer verification — equivalent to the
//! `requests` `verify=False` shape, but on the lower-level `urllib` /
//! raw-`ssl` API.
//!
//! [Bandit B323]: https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b323-unverified-context

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const NEEDLE_UNVERIFIED: &[u8] = b"_create_unverified_context";
const NEEDLE_CERT_NONE: &[u8] = b"verify_mode";
const CERT_NONE_TOKEN: &[u8] = b"ssl.CERT_NONE";
const CERT_NONE_WINDOW: usize = 64;

/// Family-19 probe R-URLLIB-NO-VERIFY.
#[derive(Debug, Default, Clone, Copy)]
pub struct UrllibNoVerifyRule;

impl Rule for UrllibNoVerifyRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.urllib_no_verify"
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
        "Python ssl/urllib code disables peer verification (Bandit B323)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if !is_python_path(&path) {
                continue;
            }
            for (offset, kind) in find_offsets(bytes) {
                out.push(emit(path.clone(), bytes, offset, kind));
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

#[derive(Debug, Clone, Copy)]
enum Hit {
    UnverifiedContext,
    CertNoneAssign,
}

impl Hit {
    const fn label(self) -> &'static str {
        match self {
            Self::UnverifiedContext => "_create_unverified_context",
            Self::CertNoneAssign => "verify_mode = ssl.CERT_NONE",
        }
    }
}

fn find_offsets(bytes: &[u8]) -> Vec<(usize, Hit)> {
    let mut hits = Vec::new();
    collect_unverified(bytes, &mut hits);
    collect_cert_none(bytes, &mut hits);
    hits.sort_unstable_by_key(|(off, _)| *off);
    hits
}

/// Find every `_create_unverified_context` substring; each one is a
/// hit unless it shares a name-byte boundary with surrounding ASCII
/// (defensive — the symbol is distinctive enough that boundaries are
/// rarely a problem in real code).
fn collect_unverified(bytes: &[u8], out: &mut Vec<(usize, Hit)>) {
    let mut i = 0;
    while i + NEEDLE_UNVERIFIED.len() <= bytes.len() {
        if &bytes[i..i + NEEDLE_UNVERIFIED.len()] == NEEDLE_UNVERIFIED {
            out.push((i, Hit::UnverifiedContext));
            i += NEEDLE_UNVERIFIED.len();
        } else {
            i += 1;
        }
    }
}

/// Find every `verify_mode` substring whose RHS within
/// [`CERT_NONE_WINDOW`] bytes contains `ssl.CERT_NONE`.
fn collect_cert_none(bytes: &[u8], out: &mut Vec<(usize, Hit)>) {
    let mut i = 0;
    while i + NEEDLE_CERT_NONE.len() <= bytes.len() {
        if &bytes[i..i + NEEDLE_CERT_NONE.len()] == NEEDLE_CERT_NONE
            && rhs_has_cert_none(bytes, i + NEEDLE_CERT_NONE.len())
        {
            out.push((i, Hit::CertNoneAssign));
            i += NEEDLE_CERT_NONE.len();
        } else {
            i += 1;
        }
    }
}

fn rhs_has_cert_none(bytes: &[u8], start: usize) -> bool {
    let cap = (start + CERT_NONE_WINDOW).min(bytes.len());
    if start >= cap {
        return false;
    }
    bytes[start..cap]
        .windows(CERT_NONE_TOKEN.len())
        .any(|w| w == CERT_NONE_TOKEN)
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize, kind: Hit) -> Finding {
    let snippet = snippet_around(bytes, offset, 96);
    let location = location_for_offset(path, bytes, offset);
    let label = kind.label();
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.urllib_no_verify",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("Python TLS verification disabled via `{label}`"),
        explanation: "Python's `ssl` module exposes two well-known TLS \
             escape hatches: `ssl._create_unverified_context()` and \
             `SSLContext.verify_mode = ssl.CERT_NONE`. Either bypasses \
             certificate-chain validation entirely. Bandit B323 catches \
             both."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Drop the unverified context. Use `ssl.create_default_context()` \
             with the system trust store, or pass an explicit `cafile=` for \
             private CAs. Tests should hit fixture servers with known \
             certs, not bypass verification."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
