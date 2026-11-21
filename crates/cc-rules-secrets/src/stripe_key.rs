//! `cc.config.stripe_key` — flag Stripe live API keys.
//!
//! Two forms are detected:
//!
//! - `sk_live_…` — **secret** live key. Server-side; full account
//!   access. ([gitleaks `stripe-access-token`])
//! - `pk_live_…` — **publishable** live key. Client-side; lower-risk,
//!   but still a leaked credential and treated identically here.
//!
//! Body must be 24+ alphanumeric characters. `sk_test_` / `pk_test_`
//! variants are skipped — Stripe documents test keys as safe-to-publish.
//!
//! [gitleaks `stripe-access-token`]: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_doc_extension, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const SK_PREFIX: &[u8] = b"sk_live_";
const PK_PREFIX: &[u8] = b"pk_live_";
const MIN_BODY_LEN: usize = 24;

/// Family-19 probe R-STRIPE-KEY.
#[derive(Debug, Default, Clone, Copy)]
pub struct StripeKeyRule;

impl Rule for StripeKeyRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.stripe_key"
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
        "Stripe live API key (sk_live_… / pk_live_…) in source bytes"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if is_doc_extension(&path) {
                continue;
            }
            for (offset, len, is_secret) in find_stripe_offsets(bytes) {
                out.push(emit(path.clone(), bytes, offset, len, is_secret));
            }
        }
        out
    }
}

/// Yield `(offset, length, is_secret_key)` triples. `is_secret_key` is
/// true for `sk_live_` (server-side) and false for `pk_live_`
/// (publishable) — the headline reflects the distinction.
fn find_stripe_offsets(bytes: &[u8]) -> Vec<(usize, usize, bool)> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some((len, is_secret)) = match_at(bytes, i) {
            hits.push((i, len, is_secret));
            i += len;
        } else {
            i += 1;
        }
    }
    hits
}

fn match_at(bytes: &[u8], i: usize) -> Option<(usize, bool)> {
    if let Some(len) = match_prefix(bytes, i, SK_PREFIX) {
        return Some((len, true));
    }
    if let Some(len) = match_prefix(bytes, i, PK_PREFIX) {
        return Some((len, false));
    }
    None
}

fn match_prefix(bytes: &[u8], i: usize, prefix: &[u8]) -> Option<usize> {
    if i + prefix.len() + MIN_BODY_LEN > bytes.len() {
        return None;
    }
    if &bytes[i..i + prefix.len()] != prefix {
        return None;
    }
    let mut j = i + prefix.len();
    while j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
        j += 1;
    }
    let body_len = j - (i + prefix.len());
    if body_len >= MIN_BODY_LEN {
        Some(j - i)
    } else {
        None
    }
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize, len: usize, is_secret: bool) -> Finding {
    let snippet = snippet_around(bytes, offset, len);
    let location = location_for_offset(path, bytes, offset);
    let kind_label = if is_secret {
        "secret key (sk_live_)"
    } else {
        "publishable key (pk_live_)"
    };
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.stripe_key",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("Stripe live {kind_label} in source"),
        explanation: "A Stripe live API key was found in source bytes. Live secret \
             keys (`sk_live_…`) authorise full charges + refunds + customer \
             access; live publishable keys (`pk_live_…`) are lower-risk but \
             still constitute a leaked credential."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Roll the key in the Stripe dashboard (Developers -> API keys -> \
             Roll secret key) and replace every reference. Use restricted \
             keys with the minimum capability set per service. Move the \
             value to a secret manager."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
