//! `cc.config.gosec_tls_insecure_skip_verify` — Go
//! `tls.Config{ InsecureSkipVerify: true }`.
//!
//! Mirrors [gosec G402] (`Look for bad TLS connection settings`). When
//! a TLS client sets `InsecureSkipVerify: true`, the runtime accepts
//! any certificate the server presents — including one signed by a
//! local attacker's CA. Any active network attacker can MITM the
//! connection and the client will accept it.
//!
//! Detection: source-byte scan for `InsecureSkipVerify: true` /
//! `InsecureSkipVerify:true` / `InsecureSkipVerify : true` in `.go`
//! files.

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const NEEDLE: &[u8] = b"InsecureSkipVerify";

/// Family-19 probe R-GOSEC-TLS-INSECURE.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecTlsInsecureSkipVerifyRule;

impl Rule for GosecTlsInsecureSkipVerifyRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.gosec_tls_insecure_skip_verify"
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
        "Go tls.Config with InsecureSkipVerify: true (gosec G402)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if !is_go_source(&path) {
                continue;
            }
            for offset in find_skip_verify_assignments(bytes) {
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

/// Find every offset where `InsecureSkipVerify` is assigned the literal
/// boolean `true` (allowing optional whitespace around `:` / `=`).
fn find_skip_verify_assignments(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i + NEEDLE.len() <= bytes.len() {
        if &bytes[i..i + NEEDLE.len()] == NEEDLE && left_word_boundary(bytes, i) {
            let after = i + NEEDLE.len();
            if assignment_is_true(bytes, after) {
                hits.push(i);
                i = after;
                continue;
            }
        }
        i += 1;
    }
    hits
}

fn left_word_boundary(bytes: &[u8], i: usize) -> bool {
    if i == 0 {
        return true;
    }
    let prev = bytes[i - 1];
    !prev.is_ascii_alphanumeric() && prev != b'_'
}

/// True iff bytes from `start` look like `[ws]*[:=][ws]*true[non-name]`.
fn assignment_is_true(bytes: &[u8], start: usize) -> bool {
    let assign = skip_ws(bytes, start);
    if !matches!(bytes.get(assign), Some(&b':') | Some(&b'=')) {
        return false;
    }
    let after_op = skip_ws(bytes, assign + 1);
    let end = after_op + 4;
    if end > bytes.len() {
        return false;
    }
    if &bytes[after_op..end] != b"true" {
        return false;
    }
    end == bytes.len() || !is_name_byte(bytes[end])
}

fn skip_ws(bytes: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\r') {
        j += 1;
    }
    j
}

const fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, 96);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.gosec_tls_insecure_skip_verify",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline:
            "Go `tls.Config{InsecureSkipVerify: true}` disables TLS verification (gosec G402)"
                .into(),
        explanation: "`InsecureSkipVerify: true` makes the TLS client \
             accept any certificate the server presents, including one \
             signed by a local attacker's CA. gosec G402 catches the same \
             pattern. In production this is equivalent to running \
             plaintext: every active MITM succeeds."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Drop `InsecureSkipVerify`. If the target really uses a \
             private CA, populate `RootCAs` with an `x509.CertPool` \
             holding that CA. Tests should hit a fixture server with a \
             known cert, not bypass verification."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
