//! `cc.config.private_key_pem` — flag PEM-encoded private-key headers
//! (`-----BEGIN [type] PRIVATE KEY-----`) anywhere in scanned source.
//!
//! Mirrors the [gitleaks `private-key`] rule. The header is the
//! distinguishing feature — once a probe sees `-----BEGIN ` followed by
//! at least one ASCII-uppercase / space character and the literal
//! `PRIVATE KEY-----`, the surrounding base-64 body is irrelevant to
//! the detection.
//!
//! Confidence is held at 0.95 (Required) rather than 0.98 (Blocker) so
//! a fresh keypair accidentally pasted into a doc fixture does not
//! mass-fail self-host. The remediation guides the user to either
//! rotate the key or move it under `tests/fixtures/`.
//!
//! [gitleaks `private-key`]: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const HEADER_PREFIX: &[u8] = b"-----BEGIN ";
const HEADER_SUFFIX: &[u8] = b" PRIVATE KEY-----";

/// Family-19 probe R-PRIVATE-KEY-PEM.
#[derive(Debug, Default, Clone, Copy)]
pub struct PrivateKeyPemRule;

impl Rule for PrivateKeyPemRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.private_key_pem"
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
        "PEM-encoded private-key header in source (RSA/DSA/EC/OPENSSH PRIVATE KEY)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if let Some(offset) = find_private_key_header(bytes) {
                out.push(emit(path, bytes, offset));
            }
        }
        out
    }
}

/// Find the first `-----BEGIN <TYPE> PRIVATE KEY-----` header in
/// `bytes`. `<TYPE>` may be either a single uppercase token (e.g.
/// `RSA`, `EC`, `OPENSSH`) or a multi-token sequence (`ENCRYPTED`,
/// `EC ENCRYPTED`). Spaces inside the type are allowed; the suffix
/// is matched as `" PRIVATE KEY-----"` so the trailing space is part
/// of the suffix, not the body.
fn find_private_key_header(bytes: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + HEADER_PREFIX.len() + HEADER_SUFFIX.len() <= bytes.len() {
        if &bytes[i..i + HEADER_PREFIX.len()] != HEADER_PREFIX {
            i += 1;
            continue;
        }
        let body_start = i + HEADER_PREFIX.len();
        if let Some(end) = match_pem_body(bytes, body_start) {
            if suffix_matches(bytes, end) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Walk forward over uppercase-ASCII bytes (and *interior* spaces)
/// until the suffix `" PRIVATE KEY-----"` is reached. The body must
/// have at least one uppercase byte to be a real key type.
fn match_pem_body(bytes: &[u8], start: usize) -> Option<usize> {
    let mut j = start;
    let mut saw_alpha = false;
    while j < bytes.len() {
        let b = bytes[j];
        if b.is_ascii_uppercase() {
            saw_alpha = true;
            j += 1;
            continue;
        }
        if b == b' ' && suffix_matches(bytes, j) {
            return saw_alpha.then_some(j);
        }
        if b == b' ' {
            j += 1;
            continue;
        }
        break;
    }
    None
}

/// Cheap suffix probe — true iff `bytes[at..]` begins with
/// `" PRIVATE KEY-----"`.
fn suffix_matches(bytes: &[u8], at: usize) -> bool {
    at + HEADER_SUFFIX.len() <= bytes.len() && &bytes[at..at + HEADER_SUFFIX.len()] == HEADER_SUFFIX
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, 64);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.private_key_pem",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "PEM private-key header present in checked-in file".into(),
        explanation: "A `-----BEGIN [...] PRIVATE KEY-----` header was \
             found in source bytes. Even a sample / staging keypair counts \
             as compromised the moment it lives in a Git history — public \
             scanners pick PEM blocks up within minutes."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Treat the key as compromised: rotate at the issuer (CA, Vault, \
             SSH `authorized_keys`, GitHub deploy-key, etc.), purge from \
             history (`git filter-repo --invert-paths`), and move new \
             material into a secret manager. If this is fixture data, move \
             the file under `tests/fixtures/` or `corpus/` so this rule's \
             skip-list applies."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
