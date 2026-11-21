//! `cc.config.subprocess_shell_true` — flag Python `subprocess.<fn>(…,
//! shell=True)` calls whose first argument is a string literal.
//!
//! Mirrors [Bandit B602] (`subprocess_popen_with_shell_equals_true`).
//! `shell=True` with a string command-line invokes `/bin/sh -c <cmd>`,
//! which means any `$VAR` / backtick expansion inside `cmd` runs as a
//! shell command. If `cmd` was assembled from untrusted input, this
//! is direct shell injection.
//!
//! Detection: source-byte scan for `subprocess.<fn>("...", ...,
//! shell=True)` or the equivalent `Popen(...)`, `call(...)`, `run(...)`
//! variants. The first argument must start with `"` or `'` for the
//! finding to fire — list-form first args (`["ls", "-la"]`) are safe
//! and intentionally ignored.

use camino::Utf8PathBuf;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, iter_scannable_files, location_for_offset, snippet_around,
    SecretsFindingBlueprint,
};

const FNS: &[&[u8]] = &[b"run", b"Popen", b"call", b"check_call", b"check_output"];
const KW_NEEDLE: &[u8] = b"shell=True";
const SCAN_WINDOW: usize = 512;

/// Family-19 probe R-SUBPROC-SHELL-TRUE.
#[derive(Debug, Default, Clone, Copy)]
pub struct SubprocessShellTrueRule;

impl Rule for SubprocessShellTrueRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.subprocess_shell_true"
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
        "Python subprocess call with shell=True and a string command (Bandit B602)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in iter_scannable_files(ctx) {
            if !is_python_path(&path) {
                continue;
            }
            for offset in find_unsafe_calls(bytes) {
                out.push(emit(path.clone(), bytes, offset));
            }
        }
        out
    }
}

fn is_python_path(path: &Utf8PathBuf) -> bool {
    matches!(
        path.extension().map(str::to_ascii_lowercase).as_deref(),
        Some("py")
    )
}

fn find_unsafe_calls(bytes: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    for fn_name in FNS {
        find_fn_hits(bytes, fn_name, &mut hits);
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

fn find_fn_hits(bytes: &[u8], fn_name: &[u8], out: &mut Vec<usize>) {
    let mut i = 0;
    while i + fn_name.len() + 1 < bytes.len() {
        if matches_fn_call(bytes, i, fn_name) {
            let after = i + fn_name.len() + 1;
            if first_arg_is_string(bytes, after) && window_has_kw(bytes, after, KW_NEEDLE) {
                out.push(i);
            }
        }
        i += 1;
    }
}

/// True iff `bytes[i..]` opens an `<fn_name>(` call with a left-side
/// word boundary (so `myrun(` does not match `run(`).
fn matches_fn_call(bytes: &[u8], i: usize, fn_name: &[u8]) -> bool {
    let body_end = i + fn_name.len();
    if body_end + 1 > bytes.len() {
        return false;
    }
    if &bytes[i..body_end] != fn_name {
        return false;
    }
    if bytes.get(body_end) != Some(&b'(') {
        return false;
    }
    if i == 0 {
        return true;
    }
    let prev = bytes[i - 1];
    !prev.is_ascii_alphanumeric() && prev != b'_'
}

/// True iff the first non-whitespace byte after the open-paren is a
/// quote character — the first arg is a string literal.
fn first_arg_is_string(bytes: &[u8], start: usize) -> bool {
    let mut j = start;
    while j < bytes.len() {
        let b = bytes[j];
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            j += 1;
            continue;
        }
        return b == b'"' || b == b'\'';
    }
    false
}

/// Bounded forward scan for `needle` until either the matching `)` at
/// depth 0 or [`SCAN_WINDOW`] bytes elapse. Same shape as the
/// `requests_no_verify` window scan.
fn window_has_kw(bytes: &[u8], start: usize, needle: &[u8]) -> bool {
    let cap = (start + SCAN_WINDOW).min(bytes.len());
    let mut depth = 1i32;
    let mut j = start;
    while j < cap {
        match bytes[j] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return slice_contains(&bytes[start..j], needle);
                }
            }
            _ => {}
        }
        j += 1;
    }
    slice_contains(&bytes[start..cap], needle)
}

fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn emit(path: Utf8PathBuf, bytes: &[u8], offset: usize) -> Finding {
    let snippet = snippet_around(bytes, offset, 96);
    let location = location_for_offset(path, bytes, offset);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.subprocess_shell_true",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: "`subprocess` called with `shell=True` on a string command".into(),
        explanation: "`subprocess.<fn>(\"...\", shell=True)` runs the \
             string through `/bin/sh -c`. Any `$VAR`, backtick, or `;` in \
             the string is interpreted by the shell. If the string is \
             built from untrusted input the call becomes direct shell \
             injection (Bandit B602)."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Pass the command as a list (`subprocess.run([\"ls\", \"-la\"])`) \
             with `shell=False` (the default). If you must shell-escape, \
             use `shlex.quote` and document the trust boundary."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
