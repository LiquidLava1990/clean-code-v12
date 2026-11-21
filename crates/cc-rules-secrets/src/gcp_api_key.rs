//! `cc.config.gcp_api_key` — flag Google Cloud API-key literals
//! (`AIza` prefix + 35 base-64-url characters) in scanned source bytes.
//!
//! Mirrors the [gitleaks `gcp-api-key`] rule. The 39-character total
//! length and `AIza` prefix are reliable enough that the heuristic
//! lands at confidence 0.9 (Required).
//!
//! [gitleaks `gcp-api-key`]: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_doc_extension, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const PREFIX: &[u8] = b"AIza";
const TAIL_LEN: usize = 35;
const TOTAL_LEN: usize = PREFIX.len() + TAIL_LEN;

/// Family-19 probe R-GCP-API-KEY.
#[derive(Debug, Default, Clone, Copy)]
pub struct GcpApiKeyRule;

impl Rule for GcpApiKeyRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.gcp_api_key"
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
        "Google Cloud API key (AIza…) pattern in source bytes"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if is_doc_extension(&path) {
                continue;
            }
            for offset in find_gcp_offsets(bytes) {
                out.push(emit(path.clone(), bytes, offset));
            }
        }
        out
    }
}

fn find_gcp_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i + TOTAL_LEN <= bytes.len() {
        if matches_gcp_at(bytes, i) {
            hits.push(i);
            i += TOTAL_LEN;
        } else {
            i += 1;
        }
    }
    hits
}

/// True iff offset `i` starts an `AIza` + 35-byte base-64-url-ish tail.
/// Caller guarantees `i + TOTAL_LEN <= bytes.len()`.
fn matches_gcp_at(bytes: &[u8], i: usize) -> bool {
    if &bytes[i..i + PREFIX.len()] != PREFIX {
        return false;
    }
    bytes[i + PREFIX.len()..i + TOTAL_LEN]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, TOTAL_LEN);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.gcp_api_key",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: "possible Google Cloud API key checked into source".into(),
        explanation: "An `AIza…` 39-character API-key shape was found in \
             source bytes. GCP keys grant project-level access; once a \
             scraper picks the key up, billing fraud and data exfil follow \
             within hours."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Rotate via the GCP console (APIs & Services -> Credentials -> \
             Restrict / Delete). Move the value to Secret Manager and \
             reference it through your runtime config layer. Restrict \
             allowed APIs + referrers to limit blast radius."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
