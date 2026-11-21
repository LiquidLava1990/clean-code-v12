//! `cc.api.struct_tag_required` — Go exported struct field with no
//! JSON / YAML tag in a struct that already tags its other exported
//! fields.
//!
//! When a struct serialises to JSON / YAML, every exported field
//! contributes to the wire shape. If most fields carry explicit tags
//! (`json:"id"`, `yaml:"name"`) but one is missing, that field still
//! ships — it just ships under the Go-cased default key, which usually
//! breaks the contract clients expect. The inconsistency is the bug.
//!
//! OSS source: golangci-lint `musttag`.
//!
//! Phase-8 source-byte heuristic (`.go` only): walk every `type Foo
//! struct {` block, count exported fields with and without tags; if at
//! least one tagged field exists in the struct, every other exported
//! field must also be tagged.
//!
//! Confidence 0.85 — the heuristic misses anonymous embedded types
//! (those carry no tag and are intentionally untagged) and method
//! receivers on partial-tag structs.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, is_test_file_path, ApiFindingBlueprint};

/// Family-9 probe R-API-STRUCT-TAG-REQUIRED.
#[derive(Debug, Default, Clone, Copy)]
pub struct StructTagRequiredRule;

impl Rule for StructTagRequiredRule {
    fn rule_id(&self) -> &'static str {
        "cc.api.struct_tag_required"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Api
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Go exported struct field missing a serialisation tag in a tagged struct"
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
            if is_test_file_path(&path) {
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
    let lines: Vec<&str> = text.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let Some(struct_name) = parse_struct_header(line) else {
            continue;
        };
        let Some(end) = find_struct_end(&lines, idx) else {
            continue;
        };
        scan_struct_body(StructScanInputs {
            path,
            lines: &lines,
            header_idx: idx,
            end_idx: end,
            struct_name,
            out,
        });
    }
}

fn parse_struct_header(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let after_type = trimmed.strip_prefix("type ")?;
    let space = after_type.find(' ')?;
    let name = &after_type[..space];
    let rest = after_type[space + 1..].trim_start();
    if !rest.starts_with("struct {") && rest != "struct" {
        return None;
    }
    Some(name)
}

fn find_struct_end(lines: &[&str], start_idx: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    for (offset, line) in lines[start_idx..].iter().enumerate() {
        if let Some(()) = scan_line_for_struct_close(line, &mut depth) {
            return Some(start_idx + offset);
        }
    }
    None
}

/// Walk one line's characters, advancing `depth` for every brace; return
/// `Some(())` when the matching close drops depth back to zero.
fn scan_line_for_struct_close(line: &str, depth: &mut i32) -> Option<()> {
    for c in line.chars() {
        if is_brace_open(c) {
            *depth += 1;
            continue;
        }
        if !is_brace_close(c) {
            continue;
        }
        *depth -= 1;
        if *depth == 0 {
            return Some(());
        }
    }
    None
}

fn is_brace_open(c: char) -> bool {
    c == '{'
}

fn is_brace_close(c: char) -> bool {
    c == '}'
}

/// Inputs to [`scan_struct_body`] — grouped to keep the parameter count
/// low and to clarify which slices and indices belong to the same scan.
struct StructScanInputs<'a, 'b> {
    path: &'a Utf8PathBuf,
    lines: &'a [&'b str],
    header_idx: usize,
    end_idx: usize,
    struct_name: &'a str,
    out: &'a mut Vec<Finding>,
}

fn scan_struct_body(inputs: StructScanInputs<'_, '_>) {
    let StructScanInputs {
        path,
        lines,
        header_idx,
        end_idx,
        struct_name,
        out,
    } = inputs;
    let body = &lines[header_idx + 1..end_idx];
    let (tagged, untagged) = classify_struct_fields(body, header_idx);
    if tagged.is_empty() {
        return;
    }
    for (line_idx, name, line) in untagged {
        out.push(emit(path.clone(), line_idx + 1, line, struct_name, name));
    }
}

/// Walk a struct body and split its exported fields into tagged names
/// and untagged `(line_no, name, raw_line)` triples.
fn classify_struct_fields<'a>(
    body: &[&'a str],
    header_idx: usize,
) -> (Vec<&'a str>, Vec<(usize, &'a str, &'a str)>) {
    let mut tagged: Vec<&str> = Vec::new();
    let mut untagged: Vec<(usize, &str, &str)> = Vec::new();
    for (idx, line) in body.iter().enumerate() {
        let Some(field) = parse_field_line(line) else {
            continue;
        };
        if !is_exported(field.name) {
            continue;
        }
        if field.has_tag {
            tagged.push(field.name);
        } else {
            untagged.push((header_idx + 1 + idx, field.name, line));
        }
    }
    (tagged, untagged)
}

#[derive(Debug)]
struct FieldLine<'a> {
    name: &'a str,
    has_tag: bool,
}

fn parse_field_line(line: &str) -> Option<FieldLine<'_>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("//") || trimmed == "}" {
        return None;
    }
    let mut tokens = trimmed.split_whitespace();
    let name = tokens.next()?;
    if !is_simple_ident(name) {
        return None;
    }
    let _type = tokens.next()?;
    let has_tag = trimmed.contains('`');
    Some(FieldLine { name, has_tag })
}

fn is_simple_ident(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_alphanumeric() || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
}

fn is_exported(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
}

fn emit(
    path: Utf8PathBuf,
    line_no: usize,
    line: &str,
    struct_name: &str,
    field_name: &str,
) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: Some(struct_name.to_owned()),
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(ApiFindingBlueprint {
        rule_id: "cc.api.struct_tag_required",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "`{struct_name}.{field_name}` is exported but has no struct tag (peers do)"
        ),
        explanation: format!(
            "Struct `{struct_name}` tags some of its exported fields with \
             `json:` / `yaml:` annotations, but `{field_name}` has no tag. \
             It still serialises — under Go's title-case default — so the \
             wire shape silently includes a field clients did not opt in \
             to. Either give `{field_name}` an explicit tag or, if it must \
             stay private, lower-case the name."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Add an explicit serialisation tag — e.g. \
             `` `json:\"field_name,omitempty\"` `` — to align with the \
             other exported fields. If the field should not appear on the \
             wire, mark it with `` `json:\"-\"` ``."
                .into(),
        ),
        snippet,
        weight: 2,
    })
}
