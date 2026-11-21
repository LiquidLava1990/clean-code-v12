//! `cc.config.github_pat` — flag GitHub Personal Access Tokens.
//!
//! Two forms are detected:
//!
//! - **Classic** — `ghp_` + 36 alphanumeric characters
//!   ([gitleaks `github-pat`]).
//! - **Fine-grained** — `github_pat_` + 82 alphanumeric / underscore
//!   characters ([gitleaks `github-fine-grained-pat`]).
//!
//! GitHub auto-revokes tokens posted to the public commit graph, but
//! anything pushed to a private mirror or fork escapes that net.
//!
//! [gitleaks `github-pat`]: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
//! [gitleaks `github-fine-grained-pat`]: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_doc_extension, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const CLASSIC_PREFIX: &[u8] = b"ghp_";
const CLASSIC_TAIL: usize = 36;
const FINE_PREFIX: &[u8] = b"github_pat_";
const FINE_TAIL: usize = 82;

/// Family-19 probe R-GITHUB-PAT.
#[derive(Debug, Default, Clone, Copy)]
pub struct GithubPatRule;

impl Rule for GithubPatRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.github_pat"
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
        "GitHub Personal Access Token (ghp_… or github_pat_…) in source bytes"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if is_doc_extension(&path) {
                continue;
            }
            for offset in find_pat_offsets(bytes) {
                out.push(emit(path.clone(), bytes, offset));
            }
        }
        out
    }
}

/// Scan `bytes` for both classic and fine-grained PAT shapes. Each hit
/// is reported once; overlapping prefixes (a `github_pat_` would not
/// also match `ghp_` because the underscore sequence breaks the body
/// charset of the classic form) are not a concern.
fn find_pat_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(skip) = match_at(bytes, i) {
            hits.push(i);
            i += skip;
        } else {
            i += 1;
        }
    }
    hits
}

/// Match either PAT form starting at `i`. Returns `Some(consumed_len)`
/// on a hit so the outer loop can skip past the matched body.
fn match_at(bytes: &[u8], i: usize) -> Option<usize> {
    if matches_classic(bytes, i) {
        return Some(CLASSIC_PREFIX.len() + CLASSIC_TAIL);
    }
    if matches_fine(bytes, i) {
        return Some(FINE_PREFIX.len() + FINE_TAIL);
    }
    None
}

fn matches_classic(bytes: &[u8], i: usize) -> bool {
    let total = CLASSIC_PREFIX.len() + CLASSIC_TAIL;
    if i + total > bytes.len() {
        return false;
    }
    if &bytes[i..i + CLASSIC_PREFIX.len()] != CLASSIC_PREFIX {
        return false;
    }
    bytes[i + CLASSIC_PREFIX.len()..i + total]
        .iter()
        .all(u8::is_ascii_alphanumeric)
}

fn matches_fine(bytes: &[u8], i: usize) -> bool {
    let total = FINE_PREFIX.len() + FINE_TAIL;
    if i + total > bytes.len() {
        return false;
    }
    if &bytes[i..i + FINE_PREFIX.len()] != FINE_PREFIX {
        return false;
    }
    bytes[i + FINE_PREFIX.len()..i + total]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, FINE_PREFIX.len() + FINE_TAIL);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.github_pat",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "GitHub Personal Access Token in source".into(),
        explanation: "A `ghp_…` (classic) or `github_pat_…` (fine-grained) \
             PAT was found in source bytes. PATs grant API access at the \
             owning user's permission level — including private repos, \
             org admin, and packages — until manually revoked."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Revoke at https://github.com/settings/tokens immediately, then \
             generate a new token scoped to the minimum permission set + \
             shortest expiry your workflow tolerates. Move the value to a \
             secret manager and reference it via env."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
