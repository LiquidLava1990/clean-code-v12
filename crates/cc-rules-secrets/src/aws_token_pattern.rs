//! `cc.config.aws_token_pattern` — flag AWS access-key / session-key
//! literals (`AKIA…` / `ASIA…`) anywhere in scanned source bytes.
//!
//! Mirrors the [gitleaks `aws-access-token`] rule. Scans every file's
//! raw bytes (not the AST), so the probe catches leaks in YAML configs,
//! shell scripts, `.tf` files, and any other text that the language
//! frontends do not expose as a `Literal` node.
//!
//! Confidence: 0.95 — the prefix + 16 base-32-uppercase tail is
//! distinctive enough that false positives are vanishingly rare. Test
//! fixtures (`tests/fixtures/`, `corpus/`, `**/fixtures/**`) and
//! Markdown / plain-text docs are skipped via the standard helpers.
//!
//! [gitleaks `aws-access-token`]: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_doc_extension, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

/// Family-19 probe R-AWS-TOKEN.
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsTokenPatternRule;

impl Rule for AwsTokenPatternRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.aws_token_pattern"
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
        "AWS access-key (AKIA…) or session-key (ASIA…) pattern in source bytes"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if is_doc_extension(&path) {
                continue;
            }
            scan_file(&path, bytes, &mut out);
        }
        out
    }
}

fn scan_file(path: &Utf8PathBuf, bytes: &[u8], out: &mut Vec<Finding>) {
    for offset in find_aws_token_offsets(bytes) {
        out.push(emit(path.clone(), bytes, offset));
    }
}

/// Walk `bytes` byte-by-byte and yield each offset where an AWS access
/// or session token starts. The match is exactly 20 bytes long: a
/// 4-byte prefix (`AKIA` or `ASIA`) followed by 16 ASCII upper / digit
/// characters. The check is greedy on the prefix only, so abutting
/// keys (rare) are all reported.
fn find_aws_token_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i + 20 <= bytes.len() {
        if matches_aws_token_at(bytes, i) {
            hits.push(i);
            i += 20;
        } else {
            i += 1;
        }
    }
    hits
}

/// True iff offset `i` of `bytes` is the start of an `AKIA` or `ASIA`
/// 20-byte token. Caller must guarantee `i + 20 <= bytes.len()`.
fn matches_aws_token_at(bytes: &[u8], i: usize) -> bool {
    let prefix = &bytes[i..i + 4];
    let prefix_ok = prefix == b"AKIA" || prefix == b"ASIA";
    if !prefix_ok {
        return false;
    }
    bytes[i + 4..i + 20]
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, 20);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.aws_token_pattern",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "possible AWS access key checked into source".into(),
        explanation: "An `AKIA…` / `ASIA…` 20-character access-key shape \
             was found in source bytes. AWS rotates leaked keys reactively, \
             but anyone who scrapes the repo before rotation has free \
             account-level access until billing or CloudTrail catches up."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Rotate the key NOW (IAM console -> deactivate + delete), then \
             move the value behind AWS Secrets Manager / SSM Parameter Store \
             / a runtime-injected env var. If this is a test fixture, move \
             the file under `tests/fixtures/` or `corpus/` so this rule's \
             skip-list applies."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
