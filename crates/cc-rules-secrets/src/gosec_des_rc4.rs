//! `cc.config.gosec_des_rc4` — Go `crypto/des` / `crypto/rc4` use.
//!
//! Mirrors [gosec G401] / G502 / G503. DES (single-DES) is broken by
//! brute-force in hours and Triple-DES (`NewTripleDESCipher`) is
//! deprecated. RC4 has practical biases that recover the keystream;
//! CRYPTREC, NIST, and IETF have all withdrawn it. Any modern code
//! reaching for either is a bug regardless of the keyword context.
//!
//! Detection: source-byte scan for `des.NewCipher(`,
//! `des.NewTripleDESCipher(`, `rc4.NewCipher(` in `.go` files.

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const PATTERNS: &[&[u8]] = &[
    b"des.NewCipher(",
    b"des.NewTripleDESCipher(",
    b"rc4.NewCipher(",
];

/// Family-19 probe R-GOSEC-DES-RC4.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecDesRc4Rule;

impl Rule for GosecDesRc4Rule {
    fn rule_id(&self) -> &'static str {
        "cc.config.gosec_des_rc4"
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
        "Go DES / RC4 cipher constructor (gosec G401/G402)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if !is_go_source(&path) {
                continue;
            }
            for offset in find_des_rc4_calls(bytes) {
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

fn find_des_rc4_calls(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    for pat in PATTERNS {
        let mut i = 0;
        while i + pat.len() <= bytes.len() {
            if &bytes[i..i + pat.len()] == *pat && left_word_boundary(bytes, i) {
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

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, 96);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.gosec_des_rc4",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "Go DES / RC4 cipher constructor (gosec G401/G402)".into(),
        explanation: "DES (single + triple) and RC4 are broken stream / \
             block ciphers — DES is brute-forceable, RC4 has keystream \
             biases. NIST, CRYPTREC, and the IETF have withdrawn both. \
             Any new use is a real correctness bug, not a stylistic \
             preference."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Use AES-256-GCM (`crypto/cipher.NewGCM` over \
             `crypto/aes.NewCipher`) for symmetric encryption. For \
             stream-mode use ChaCha20-Poly1305 \
             (`golang.org/x/crypto/chacha20poly1305`)."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
