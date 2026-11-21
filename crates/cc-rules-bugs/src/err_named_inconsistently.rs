//! `cc.bug.err_named_inconsistently` — Go error sentinel variables not
//! prefixed with `Err` (exported) / `err` (unexported).
//!
//! The Go community convention since 2016 is that error-typed package
//! variables are named with a leading `Err` (exported) or `err`
//! (unexported), so call sites read like `errors.Is(got, mypkg.ErrFoo)`.
//! Mis-named sentinels (`SomethingError`, `FooErr`, `BadInput`) make
//! `errors.Is` chains harder to grep and inconsistent with the standard
//! library.
//!
//! OSS source: golangci `errname`.
//!
//! Phase-9 source-byte heuristic: `.go` files only. Detect top-level
//! `var <name> = errors.New(...)` / `var <name> = fmt.Errorf(...)` /
//! `var <name> error = ...` declarations whose `<name>` does not start
//! with the canonical prefix. Skip `_test.go` for safety.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, looks_like_rule_pack_source, BugFindingBlueprint};

/// Family-3 probe R-ERR-NAMED-INCONSISTENTLY.
#[derive(Debug, Default, Clone, Copy)]
pub struct ErrNamedInconsistentlyRule;

impl Rule for ErrNamedInconsistentlyRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.err_named_inconsistently"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Go error sentinel must be named `Err...` (exported) or `err...` (unexported)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("go") {
                continue;
            }
            if is_go_test_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn is_go_test_path(path: &Utf8PathBuf) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_ascii_lowercase().ends_with("_test.go"))
}

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        let Some(name) = parse_error_sentinel_name(line) else {
            continue;
        };
        if has_canonical_prefix(&name) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, line, &name));
    }
}

/// Match patterns like:
/// - `var SomeError = errors.New("...")`
/// - `var Foo = fmt.Errorf("...")`
/// - `SomeError = errors.New("...")` (top-level rebind, rare)
fn parse_error_sentinel_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let after_var = trimmed.strip_prefix("var ")?;
    if !line_constructs_error(after_var) {
        return None;
    }
    let assign_idx = after_var.find('=')?;
    let lhs = after_var[..assign_idx].trim();
    extract_first_identifier(lhs)
}

/// True iff the RHS clearly constructs an `error` value. Closed list:
/// `errors.New` and `fmt.Errorf` are the two stdlib paths.
fn line_constructs_error(after_var: &str) -> bool {
    after_var.contains("errors.New(") || after_var.contains("fmt.Errorf(")
}

fn extract_first_identifier(lhs: &str) -> Option<String> {
    let head = lhs.split(|c: char| c == ',' || c.is_whitespace()).next()?;
    let name: String = head
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Canonical: exported sentinels start with `Err`, unexported with
/// `err`. Anything else is the violation.
fn has_canonical_prefix(name: &str) -> bool {
    name.starts_with("Err") || name.starts_with("err")
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, name: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: Some(name.to_owned()),
    };
    let snippet: String = line.trim().chars().take(180).collect();
    let suggested = suggest_canonical_name(name);
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.err_named_inconsistently",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "error sentinel `{name}` should be `{suggested}` (Go `errname` convention)"
        ),
        explanation: format!(
            "Go's community convention (codified in golangci `errname`) \
             names error-typed package variables `Err...` for exported \
             values and `err...` for unexported. `{name}` does not match \
             either prefix, so call-site `errors.Is(got, pkg.{name})` \
             reads inconsistently with stdlib calls like \
             `errors.Is(got, io.EOF)`."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Rename `{name}` -> `{suggested}` and update every call site. \
             A safe `gopls rename` (or `gorename`) keeps the change \
             mechanical."
        )),
        snippet,
        weight: 1,
    })
}

/// Suggest the canonical name: keep the original case sense (exported
/// vs unexported), strip a trailing `Error` / `Err` suffix if present,
/// and prefix `Err` / `err`.
fn suggest_canonical_name(original: &str) -> String {
    let exported = original
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase());
    let stem = strip_error_suffix(original);
    let head = stem.chars().next().unwrap_or('X');
    let prefix = if exported { "Err" } else { "err" };
    let head_norm = if exported {
        head.to_ascii_uppercase()
    } else {
        head.to_ascii_lowercase()
    };
    let tail: String = stem.chars().skip(1).collect();
    format!("{prefix}{head_norm}{tail}")
}

fn strip_error_suffix(name: &str) -> &str {
    for suffix in ["Error", "Err", "error", "err"] {
        if let Some(stem) = name.strip_suffix(suffix) {
            if !stem.is_empty() {
                return stem;
            }
        }
    }
    name
}
