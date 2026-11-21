//! `cc.config.generic_api_key_assignment` — heuristic for
//! `api_key|apikey|api-key|secret|token|password = "<long-value>"`
//! assignments where the RHS string is 20+ characters.
//!
//! Mirrors the [gitleaks `generic-api-key`] rule + the OWASP
//! [Hardcoded Credentials] cheat-sheet entry. Heuristic-grade — false
//! positives are inevitable on test fixtures and template strings, so
//! confidence is held at 0.85 and the standard fixture / test / doc
//! skips apply.
//!
//! [gitleaks `generic-api-key`]: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
//! [Hardcoded Credentials]: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_doc_extension, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const KEYWORDS: &[&[u8]] = &[
    b"api_key",
    b"apikey",
    b"api-key",
    b"secret",
    b"token",
    b"password",
];
const MIN_VALUE_LEN: usize = 20;

/// Family-19 probe R-GENERIC-API-KEY.
#[derive(Debug, Default, Clone, Copy)]
pub struct GenericApiKeyAssignmentRule;

impl Rule for GenericApiKeyAssignmentRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.generic_api_key_assignment"
    }
    fn category(&self) -> Category {
        Category::Config
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "credential-suffixed identifier assigned a long quoted literal"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if is_doc_extension(&path) {
                continue;
            }
            for offset in find_assignment_offsets(bytes) {
                out.push(emit(path.clone(), bytes, offset));
            }
        }
        out
    }
}

/// Walk `bytes` looking for `<keyword>\s*[:=]\s*<quote><value>...<quote>`
/// where `value` is at least [`MIN_VALUE_LEN`] base-charset bytes long.
/// Returns the offset of the keyword on each hit.
fn find_assignment_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let lower = lowercase_ascii(bytes);
    let mut i = 0;
    while i < lower.len() {
        if let Some(skip) = check_assignment_at(bytes, &lower, i) {
            hits.push(i);
            i += skip;
        } else {
            i += 1;
        }
    }
    hits
}

/// Lower-case every ASCII letter; leave non-ASCII bytes untouched. The
/// resulting buffer matches against [`KEYWORDS`] case-insensitively.
fn lowercase_ascii(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(u8::to_ascii_lowercase).collect()
}

/// Try to match a keyword + `=` / `:` + quoted long literal at `i`.
/// Returns `Some(consumed)` so the outer loop can skip past the match.
fn check_assignment_at(bytes: &[u8], lower: &[u8], i: usize) -> Option<usize> {
    let keyword = match_keyword(lower, i)?;
    if !is_keyword_word_boundary(lower, i, keyword.len()) {
        return None;
    }
    let after_kw = i + keyword.len();
    let assign_idx = skip_to_assigner(bytes, after_kw)?;
    let quote_idx = skip_to_quote(bytes, assign_idx + 1)?;
    let quote = bytes[quote_idx];
    let value_len = quoted_value_len(bytes, quote_idx + 1, quote)?;
    if value_len < MIN_VALUE_LEN {
        return None;
    }
    Some(quote_idx + 2 + value_len - i)
}

/// Find which keyword (if any) starts at `i` of `lower`.
fn match_keyword(lower: &[u8], i: usize) -> Option<&'static [u8]> {
    KEYWORDS
        .iter()
        .copied()
        .find(|kw| i + kw.len() <= lower.len() && &lower[i..i + kw.len()] == *kw)
}

/// True iff the keyword at `i` is preceded and followed by a non-name
/// boundary byte (avoids matching `password` inside `passwordless`).
fn is_keyword_word_boundary(lower: &[u8], i: usize, kw_len: usize) -> bool {
    let prev_ok = i == 0 || !is_name_byte(lower[i - 1]);
    let next_ok = i + kw_len >= lower.len() || !is_name_byte(lower[i + kw_len]);
    prev_ok && next_ok
}

const fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Walk forward from `start` skipping spaces/tabs; return the index of
/// the first byte for which `accept` is true — or `None` if the next
/// non-space byte fails the predicate.
fn skip_spaces_then<F>(bytes: &[u8], start: usize, accept: F) -> Option<usize>
where
    F: Fn(u8) -> bool,
{
    let mut j = start;
    while j < bytes.len() {
        let b = bytes[j];
        if b == b' ' || b == b'\t' {
            j += 1;
            continue;
        }
        return accept(b).then_some(j);
    }
    None
}

fn skip_to_assigner(bytes: &[u8], start: usize) -> Option<usize> {
    skip_spaces_then(bytes, start, |b| b == b'=' || b == b':')
}

fn skip_to_quote(bytes: &[u8], start: usize) -> Option<usize> {
    skip_spaces_then(bytes, start, |b| b == b'"' || b == b'\'')
}

/// Count the body length of a quoted literal whose body charset is
/// alphanumeric / `_` / `-`. Stops at the closing quote, a non-charset
/// byte, or the end of the buffer.
fn quoted_value_len(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut j = start;
    while j < bytes.len() {
        let b = bytes[j];
        if b == quote {
            return Some(j - start);
        }
        if !b.is_ascii_alphanumeric() && b != b'_' && b != b'-' {
            return None;
        }
        j += 1;
    }
    None
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, 64);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.generic_api_key_assignment",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "credential-suffixed identifier assigned a long quoted literal".into(),
        explanation: "A keyword like `api_key`, `secret`, `token`, or \
             `password` is being assigned a 20+ character quoted literal. \
             This shape catches checked-in credentials in YAML / TOML / \
             JSON / source files."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "If the value is a real credential, rotate it and load via env \
             var / secret manager. If it is fixture data, move under \
             `tests/fixtures/` or `corpus/`. If it is a placeholder, drop \
             length below 20 chars (e.g. `\"<set me>\"`) so the heuristic \
             stops firing."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
