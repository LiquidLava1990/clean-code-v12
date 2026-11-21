//! `cc.bug.govet_struct_tag_well_formed` — Go struct tag with a
//! malformed `key:"value"` pair (missing colon, unbalanced quotes,
//! whitespace inside the key, missing space between pairs).
//!
//! Canonical bug:
//! ```go
//! type User struct {
//!     Name string `json:"name"`             // OK
//!     Age  int    `json:age`                // missing quotes around value
//!     Bio  string `json: "bio"`             // space after colon
//!     Pwd  string `json:"pwd" yaml:"pwd"`   // OK (space-separated pairs)
//!     Tag  string `jsonname"`               // missing colon
//! }
//! ```
//! `go vet -structtag` (StructTag pass) parses every backtick literal
//! that follows a struct field. Reflect-based libraries (`encoding/json`,
//! `gopkg.in/yaml.v3`, `gorm`) silently ignore malformed tags, so the
//! field never serialises and the bug surfaces only as missing data.
//!
//! OSS source: `go vet -structtag` (golang.org/x/tools/go/analysis/passes/structtag).
//!
//! Phase-12 source-byte heuristic: `.go` files only (skip `_test.go`).
//! Find every line whose trailing token is a backtick-delimited tag
//! and validate the `key:"value"` shape. Report the first malformed
//! pair on the line.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.govet_struct_tag_well_formed`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GovetStructTagWellFormedRule;

impl Rule for GovetStructTagWellFormedRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.govet_struct_tag_well_formed"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "Go struct tag with malformed `key:\"value\"` pair"
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

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    for (idx, line) in text.lines().enumerate() {
        let Some(tag) = extract_tag(line) else {
            continue;
        };
        if let Some(reason) = first_malformed_pair(tag) {
            out.push(emit(path.clone(), idx + 1, line, reason));
        }
    }
}

/// Extract the backtick-delimited tag content from a struct-field line.
/// Returns `None` when the line has no tag or the tag is empty.
fn extract_tag(line: &str) -> Option<&str> {
    let first = line.find('`')?;
    let rest = &line[first + 1..];
    let close = rest.find('`')?;
    let tag = &rest[..close];
    if tag.is_empty() {
        return None;
    }
    Some(tag)
}

/// Walk the tag string, slicing into space-separated pairs. Return a
/// reason string for the first malformed pair, or `None` when every
/// pair is well-formed.
fn first_malformed_pair(tag: &str) -> Option<&'static str> {
    let bytes = tag.as_bytes();
    let mut i = skip_spaces(bytes, 0);
    while i < bytes.len() {
        let next = match parse_one_pair(tag, bytes, i) {
            Ok(n) => n,
            Err(reason) => return Some(reason),
        };
        match skip_spaces_after_pair(bytes, next) {
            Ok(advanced) => i = advanced,
            Err(reason) => return Some(reason),
        }
    }
    None
}

/// Parse a single `key:"value"` pair starting at `start`. Returns the
/// index immediately after the closing quote, or a malformation
/// reason. All scanning is inlined to keep dataflow visible to
/// downstream dead-code analysis.
fn parse_one_pair(tag: &str, bytes: &[u8], start: usize) -> Result<usize, &'static str> {
    // Walk to the colon — abort on whitespace or EOL.
    let mut i = start;
    while i < bytes.len() && bytes[i] != b':' && bytes[i] != b' ' {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b':' {
        return Err("missing `:` between key and value");
    }
    let colon = i;
    let key = &tag[start..colon];
    if key.is_empty() || !is_clean_key(key) {
        return Err("malformed key (empty or contains whitespace)");
    }
    let after_colon = colon + 1;
    if bytes.get(after_colon).copied() != Some(b'"') {
        return Err("value missing opening `\"` after `:`");
    }
    // Walk to the closing quote, honouring `\"` escapes.
    let mut j = after_colon + 1;
    while j < bytes.len() {
        if bytes[j] == b'\\' {
            j += 2;
            continue;
        }
        if bytes[j] == b'"' {
            return Ok(j + 1);
        }
        j += 1;
    }
    Err("value missing closing `\"` (unbalanced quotes)")
}

fn skip_spaces(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    i
}

/// After the closing quote of a pair, the next byte must be either
/// EOL or a single space (followed by the next pair). Anything else
/// is malformed.
fn skip_spaces_after_pair(bytes: &[u8], i: usize) -> Result<usize, &'static str> {
    if i >= bytes.len() {
        return Ok(i);
    }
    if bytes[i] != b' ' {
        return Err("pairs must be separated by a single space");
    }
    Ok(skip_spaces(bytes, i))
}

fn is_clean_key(key: &str) -> bool {
    key.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, reason: &'static str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.govet_struct_tag_well_formed",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("malformed Go struct tag: {reason}"),
        explanation: format!(
            "Go's reflect-based encoders (`encoding/json`, `yaml.v3`, \
             `gorm`, `validator`) parse struct tags as a space-separated \
             sequence of `key:\"value\"` pairs. Anything that doesn't \
             match the canonical shape is silently dropped — the field \
             then fails to (de)serialise without any compile-time \
             warning. Reason: {reason}. `go vet -structtag` catches \
             this; we replicate the check at probe time."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Rewrite the tag as `key:\"value\"` pairs separated by \
             single spaces. Example: `` `json:\"name\" yaml:\"name\" \
             validate:\"required\"` ``. No space around the colon, \
             quotes around every value, no unmatched quote escapes."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
