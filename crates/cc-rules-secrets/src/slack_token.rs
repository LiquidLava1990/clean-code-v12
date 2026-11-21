//! `cc.config.slack_token` — flag Slack workspace / bot / user tokens
//! whose canonical shape is `xox[baprs]-…` (digits, dashes, alphanum).
//!
//! Mirrors the [gitleaks `slack-access-token`] family. The minimum
//! plausible body length is 10 characters; in practice Slack tokens
//! are 24+, so the heuristic uses `len(body) >= 10` to keep the false
//! positive rate low without missing short staging tokens.
//!
//! [gitleaks `slack-access-token`]: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_doc_extension, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const PREFIX: &[u8] = b"xox";
const KIND_BYTES: &[u8] = b"baprs";
const MIN_BODY_LEN: usize = 10;

/// Family-19 probe R-SLACK-TOKEN.
#[derive(Debug, Default, Clone, Copy)]
pub struct SlackTokenRule;

impl Rule for SlackTokenRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.slack_token"
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
        "Slack token (xoxb-/xoxp-/xoxa-/xoxr-/xoxs-…) in source bytes"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if is_doc_extension(&path) {
                continue;
            }
            for (offset, len) in find_slack_offsets(bytes) {
                out.push(emit(path.clone(), bytes, offset, len));
            }
        }
        out
    }
}

/// Scan `bytes` for Slack-token shapes; yield `(start_offset, length)`
/// pairs so the snippet builder can copy the entire matched range.
fn find_slack_offsets(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i + 5 < bytes.len() {
        if let Some(len) = match_slack_at(bytes, i) {
            hits.push((i, len));
            i += len;
        } else {
            i += 1;
        }
    }
    hits
}

/// Match `xox[baprs]-<body>` at `i`. Body characters are alphanumeric
/// or `-`. Returns the matched length (including prefix) on hit.
fn match_slack_at(bytes: &[u8], i: usize) -> Option<usize> {
    if &bytes[i..i + 3] != PREFIX {
        return None;
    }
    let kind = *bytes.get(i + 3)?;
    if !KIND_BYTES.contains(&kind) {
        return None;
    }
    if bytes.get(i + 4) != Some(&b'-') {
        return None;
    }
    let mut j = i + 5;
    while j < bytes.len() {
        let b = bytes[j];
        if b.is_ascii_alphanumeric() || b == b'-' {
            j += 1;
        } else {
            break;
        }
    }
    let body_len = j - (i + 5);
    if body_len >= MIN_BODY_LEN {
        Some(j - i)
    } else {
        None
    }
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize, len: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, len.max(16));
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.slack_token",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: "Slack token checked into source".into(),
        explanation: "A Slack `xox[baprs]-…` token was found in source \
             bytes. Slack tokens carry workspace-level read/write — chat \
             history exfil, message spoofing, and DM access in one shot."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Revoke at https://api.slack.com/apps -> OAuth & Permissions, \
             rotate via the install flow, and store the new value in a \
             secret manager. Pin the bot scope list to the minimum your \
             integration needs."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
