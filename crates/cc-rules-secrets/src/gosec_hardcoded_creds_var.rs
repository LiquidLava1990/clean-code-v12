//! `cc.config.gosec_hardcoded_creds_var` — Go top-level
//! `var <CredName> = "..."` / `const <CredName> = "..."` declarations
//! whose RHS is a 20+ character alphanumeric+special string.
//!
//! Mirrors [gosec G101] (`hardcoded credentials`). Heuristic-grade —
//! confidence held at 0.85. Skip values matching obvious test
//! placeholders (`test_*`, `example_*`).
//!
//! [gosec G101]: https://github.com/securego/gosec/blob/master/rules/hardcoded_credentials.go

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const KEYWORDS: &[&[u8]] = &[b"var", b"const"];
const CRED_NAME_HINTS: &[&[u8]] = &[
    b"key",
    b"token",
    b"secret",
    b"password",
    b"passwd",
    b"pwd",
    b"apikey",
    b"auth",
    b"credential",
    b"sessionkey",
];
const PLACEHOLDER_PREFIXES: &[&[u8]] = &[
    b"test_",
    b"example_",
    b"fake_",
    b"dummy_",
    b"placeholder_",
    b"sample_",
];
const MIN_VALUE_LEN: usize = 20;

/// Family-19 probe R-GOSEC-HARDCODED-CREDS-VAR.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecHardcodedCredsVarRule;

impl Rule for GosecHardcodedCredsVarRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.gosec_hardcoded_creds_var"
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
        "Go var/const declaration assigning a 20+ char literal to a credential-shaped name (gosec G101)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if !is_go_source(&path) {
                continue;
            }
            for offset in find_creds(bytes) {
                out.push(emit(path.clone(), bytes, offset));
            }
        }
        out
    }
}

/// True iff `path` is a non-test `.go` source file.
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

/// Walk `bytes` looking for `var|const <CredName> = "<value>"` where the
/// value is a 20+ char alnum-with-special string and `CredName` carries
/// a credential hint.
fn find_creds(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let lower = bytes
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<u8>>();
    let mut i = 0;
    while i < lower.len() {
        if let Some(skip) = check_decl_at(bytes, &lower, i) {
            hits.push(i);
            i += skip;
        } else {
            i += 1;
        }
    }
    hits
}

fn check_decl_at(bytes: &[u8], lower: &[u8], i: usize) -> Option<usize> {
    let kw = match_keyword_at(lower, i)?;
    let after_kw = i + kw.len();
    if !boundary_after(bytes, i, kw.len()) {
        return None;
    }
    let name_start = skip_spaces(bytes, after_kw);
    let (name_end, name_lower) = read_identifier(lower, name_start)?;
    if !name_has_cred_hint(&name_lower) {
        return None;
    }
    let assign_idx = scan_to_equals(bytes, name_end)?;
    let quote_idx = scan_to_quote(bytes, assign_idx + 1)?;
    let value_len = quoted_value_len(bytes, quote_idx + 1)?;
    if value_len < MIN_VALUE_LEN {
        return None;
    }
    let value = &bytes[quote_idx + 1..quote_idx + 1 + value_len];
    if has_placeholder_prefix(value) {
        return None;
    }
    Some(quote_idx + 2 + value_len - i)
}

fn match_keyword_at(lower: &[u8], i: usize) -> Option<&'static [u8]> {
    KEYWORDS
        .iter()
        .copied()
        .find(|kw| i + kw.len() <= lower.len() && &lower[i..i + kw.len()] == *kw)
}

fn boundary_after(bytes: &[u8], i: usize, kw_len: usize) -> bool {
    if i > 0 && is_name_byte(bytes[i - 1]) {
        return false;
    }
    let after = i + kw_len;
    after < bytes.len() && (bytes[after] == b' ' || bytes[after] == b'\t')
}

fn skip_spaces(bytes: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    j
}

fn read_identifier(lower: &[u8], start: usize) -> Option<(usize, Vec<u8>)> {
    let mut j = start;
    while j < lower.len() && is_name_byte(lower[j]) {
        j += 1;
    }
    if j == start {
        return None;
    }
    Some((j, lower[start..j].to_vec()))
}

fn name_has_cred_hint(name_lower: &[u8]) -> bool {
    CRED_NAME_HINTS
        .iter()
        .any(|hint| slice_contains(name_lower, hint))
}

fn scan_to_equals(bytes: &[u8], start: usize) -> Option<usize> {
    scan_until(bytes, start, |b| b == b'=', |b| b == b'\n' || b == b';')
}

fn scan_to_quote(bytes: &[u8], start: usize) -> Option<usize> {
    scan_until(
        bytes,
        start,
        |b| b == b'"',
        |b| b == b'\n' || !(b == b' ' || b == b'\t'),
    )
}

fn quoted_value_len(bytes: &[u8], start: usize) -> Option<usize> {
    let end = scan_until(bytes, start, |b| b == b'"', |b| b == b'\n' || b == b'\r')?;
    Some(end - start)
}

/// Walk forward from `start`. Return the first index where `accept`
/// fires; abort with `None` the first time `bail` fires before that.
fn scan_until<A, B>(bytes: &[u8], start: usize, accept: A, bail: B) -> Option<usize>
where
    A: Fn(u8) -> bool,
    B: Fn(u8) -> bool,
{
    let mut j = start;
    while j < bytes.len() {
        let b = bytes[j];
        if accept(b) {
            return Some(j);
        }
        if bail(b) {
            return None;
        }
        j += 1;
    }
    None
}

fn has_placeholder_prefix(value: &[u8]) -> bool {
    let lower: Vec<u8> = value.iter().map(u8::to_ascii_lowercase).collect();
    PLACEHOLDER_PREFIXES.iter().any(|p| lower.starts_with(p))
}

fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

const fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, 96);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.gosec_hardcoded_creds_var",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "Go credential-shaped var/const initialised with a long literal (gosec G101)"
            .into(),
        explanation: "A package-level `var` or `const` whose name carries a \
             credential hint (key/token/secret/password/auth) is being \
             initialised with a 20+ character literal. gosec G101 catches \
             this exact pattern: a checked-in credential is recoverable by \
             anyone who can read the binary or the repo."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Move the value behind `os.Getenv` / a secrets manager / a \
             config struct loaded at startup. If this is fixture data, \
             move under `tests/fixtures/` or rename with a `test_` / \
             `example_` prefix so the heuristic stops firing."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
