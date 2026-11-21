//! `cc.taint.weak_password_hash` — MD5/SHA1 used to hash a password.
//!
//! Detects the canonical "broken hash for credentials" pattern across
//! Python, Java, and JavaScript / TypeScript:
//!
//! - **Python**: `hashlib.md5(...)` / `hashlib.sha1(...)` / `MD5.new(...)` /
//!   `SHA1.new(...)` near a `password` / `passwd` / `auth` / `credential` /
//!   `pwd` token.
//! - **Java / Kotlin**: `MessageDigest.getInstance("MD5")` /
//!   `MessageDigest.getInstance("SHA-1")` near the same tokens.
//! - **JS / TS**: `crypto.createHash('md5')` / `crypto.createHash("sha1")`
//!   near the same tokens.
//!
//! OSS source: CodeQL `py/weak-sensitive-data-hashing`,
//! `java/weak-cryptographic-algorithm`, `js/weak-cryptographic-algorithm`;
//! Sonar `java:S4790`, `python:S4426`, `javascript:S4426`; Semgrep
//! `python.lang.security.audit.weak-password-hash`.
//!
//! Phase-10 source-byte heuristic: scan supported files for a weak-hash
//! needle, then look in a ±3 line window for a credential token. Two
//! signals required keeps false positives down (a checksum on
//! non-credential data does not match).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TaintFindingBlueprint,
};

/// Family-4 probe `cc.taint.weak_password_hash`.
#[derive(Debug, Default, Clone, Copy)]
pub struct WeakPasswordHashRule;

const SUPPORTED_EXTS: &[&str] = &[
    "py", "java", "kt", "kts", "js", "jsx", "ts", "tsx", "mjs", "cjs",
];

/// Substrings whose presence indicates an MD5/SHA1 hash is being
/// constructed. Each entry is matched case-sensitively against the raw
/// line text.
const WEAK_HASH_NEEDLES: &[&str] = &[
    // Python
    "hashlib.md5(",
    "hashlib.sha1(",
    "hashlib.new(\"md5\"",
    "hashlib.new('md5'",
    "hashlib.new(\"sha1\"",
    "hashlib.new('sha1'",
    "MD5.new(",
    "SHA1.new(",
    // Java / Kotlin
    "MessageDigest.getInstance(\"MD5\")",
    "MessageDigest.getInstance(\"SHA-1\")",
    "MessageDigest.getInstance(\"SHA1\")",
    // JS / TS
    "crypto.createHash('md5')",
    "crypto.createHash(\"md5\")",
    "crypto.createHash('sha1')",
    "crypto.createHash(\"sha1\")",
];

/// Lower-case credential tokens. The presence of any token within a
/// ±3 line window of a weak-hash needle promotes the line from "checksum"
/// to "password hash".
const CREDENTIAL_TOKENS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "credential",
    "secret_token",
    "auth_token",
    "api_key",
    "apikey",
    "user_secret",
];

const PROXIMITY_WINDOW: usize = 3;

impl Rule for WeakPasswordHashRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.weak_password_hash"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Taint
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "MD5/SHA1 used to hash a password / credential — both are broken for that role"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_supported_ext(&path) {
                continue;
            }
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn is_supported_ext(path: &Utf8PathBuf) -> bool {
    path.extension()
        .is_some_and(|ext| SUPPORTED_EXTS.iter().any(|e| *e == ext))
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let lines: Vec<&str> = text.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if let Some(needle) = matched_weak_hash(line) {
            if proximity_has_credential_token(&lines, idx) {
                out.push(emit(path.clone(), idx + 1, line, needle));
            }
        }
    }
}

fn matched_weak_hash(line: &str) -> Option<&'static str> {
    WEAK_HASH_NEEDLES.iter().copied().find(|n| line.contains(n))
}

fn proximity_has_credential_token(lines: &[&str], idx: usize) -> bool {
    let lo = idx.saturating_sub(PROXIMITY_WINDOW);
    let hi = (idx + PROXIMITY_WINDOW + 1).min(lines.len());
    for window_line in &lines[lo..hi] {
        let lower = window_line.to_ascii_lowercase();
        if CREDENTIAL_TOKENS.iter().any(|t| lower.contains(t)) {
            return true;
        }
    }
    false
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, needle: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(TaintFindingBlueprint {
        rule_id: "cc.taint.weak_password_hash",
        category: cc_finding::Category::Taint,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "weak hash `{}` used near a credential token",
            needle.trim_end_matches('(')
        ),
        explanation: "MD5 and SHA-1 are cryptographically broken for password \
             hashing: collisions can be produced on commodity hardware and \
             unsalted hashes fall to rainbow tables in seconds. A password \
             token within a few lines of this hash construction is a strong \
             signal that the digest is being used to store or compare \
             credentials."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Use a memory-hard password KDF: `argon2id` (preferred), \
             `bcrypt`, or `scrypt`. For non-credential digests where \
             collision resistance is needed, use SHA-256 or BLAKE3."
                .into(),
        ),
        snippet,
        weight: 6,
    })
}
