//! `cc.config.weak_crypto` — flag calls into known-broken cryptographic
//! primitives.
//!
//! Detection table (callee name match):
//!
//! - **Python**: `hashlib.md5`, `hashlib.sha1`, `Crypto.Cipher.DES`,
//!   `Crypto.Cipher.ARC4`.
//! - **Rust**: `md5::compute`, `sha1::Sha1::new`, `des::Des`,
//!   `rc4::Rc4`.
//! - **Go**: imports of `crypto/md5`, `crypto/sha1`, `crypto/des`,
//!   `crypto/rc4` (also surfaced via callee names like `md5.New`).
//! - **JavaScript / TypeScript**: `crypto.createHash('md5')`,
//!   `crypto.createHash('sha1')`, `crypto.createCipheriv('des-…')`,
//!   `crypto.createCipheriv('rc4-…')`.
//!
//! Findings are suppressed when the surrounding three lines contain a
//! marker like `non-security`, `non-cryptographic`, or
//! `legacy hash for cache key` (case-insensitive substring).

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, range_prop, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, SecretsFindingBlueprint,
};

/// Family-19 probe R-WEAK-CRYPTO.
#[derive(Debug, Default, Clone, Copy)]
pub struct WeakCryptoRule;

impl Rule for WeakCryptoRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.weak_crypto"
    }
    fn category(&self) -> Category {
        Category::Config
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "use of broken cryptographic primitive (md5/sha1/DES/RC4)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, node.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, id: NodeId) -> Option<Finding> {
    let callee = string_prop(ctx.batch, id, "callee_ref")?;
    let weak = classify_weak_call(ctx, id, callee)?;
    let path = enclosing_file_path(ctx.batch, id)?;
    if has_non_security_marker(ctx, id, &path) {
        return None;
    }
    let location = location_from_node(ctx.batch, id, path);
    Some(build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.weak_crypto",
        category: Category::Config,
        severity: Severity::Blocker,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("`{callee}` is a broken cryptographic primitive ({weak})"),
        explanation: format!(
            "{weak} is cryptographically broken — collisions are practical and \
             ciphertexts are recoverable. Using it for any security purpose \
             (auth tokens, password hashing, key derivation, MAC) is a real \
             correctness bug, not a stylistic preference."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Replace md5/sha1 with sha256/sha3/blake3, DES with AES-256-GCM, \
             RC4 with ChaCha20-Poly1305. If the call really is for a non-\
             security cache key, add a `// non-security` comment within \
             three lines to suppress this rule."
                .into(),
        ),
        snippet: callee.to_owned(),
        weight: 5,
    }))
}

fn classify_weak_call(_ctx: &RuleContext<'_>, _id: NodeId, callee: &str) -> Option<&'static str> {
    if matches_md5(callee) {
        return Some("MD5");
    }
    if matches_sha1(callee) {
        return Some("SHA-1");
    }
    if matches_des(callee) {
        return Some("DES");
    }
    if matches_rc4(callee) {
        return Some("RC4 / ARC4");
    }
    None
}

fn matches_md5(callee: &str) -> bool {
    matches!(
        callee,
        "hashlib.md5" | "md5::compute" | "md5.New" | "crypto/md5.New" | "crypto/md5.Sum"
    ) || callee.ends_with("::md5")
        || callee == "md5"
}

fn matches_sha1(callee: &str) -> bool {
    matches!(
        callee,
        "hashlib.sha1"
            | "sha1::Sha1"
            | "sha1::Sha1::new"
            | "sha1.New"
            | "crypto/sha1.New"
            | "crypto/sha1.Sum"
    ) || callee == "sha1"
}

fn matches_des(callee: &str) -> bool {
    matches!(
        callee,
        "Crypto.Cipher.DES"
            | "Crypto.Cipher.DES.new"
            | "des::Des"
            | "des.NewCipher"
            | "crypto/des.NewCipher"
    )
}

fn matches_rc4(callee: &str) -> bool {
    matches!(
        callee,
        "Crypto.Cipher.ARC4"
            | "Crypto.Cipher.ARC4.new"
            | "rc4::Rc4"
            | "rc4.NewCipher"
            | "crypto/rc4.NewCipher"
    )
}

fn has_non_security_marker(ctx: &RuleContext<'_>, id: NodeId, path: &camino::Utf8PathBuf) -> bool {
    let Some(range) = range_prop(ctx.batch, id, "range") else {
        return false;
    };
    let bytes = ctx.source.get(path.as_path());
    let text = std::str::from_utf8(bytes).unwrap_or("");
    let context = surrounding_lines(text, range.start.line, 3);
    let lower = context.to_ascii_lowercase();
    lower.contains("non-security")
        || lower.contains("non-cryptographic")
        || lower.contains("non cryptographic")
        || lower.contains("legacy hash for cache key")
}

/// Return the lines `[centre - radius, centre + radius]` joined by `\n`.
fn surrounding_lines(text: &str, centre_1based: u32, radius: u32) -> String {
    let centre = centre_1based.saturating_sub(1) as usize;
    let lo = centre.saturating_sub(radius as usize);
    let hi = centre + radius as usize;
    text.lines()
        .enumerate()
        .filter_map(|(i, l)| (i >= lo && i <= hi).then_some(l))
        .collect::<Vec<_>>()
        .join("\n")
}
