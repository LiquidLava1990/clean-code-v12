//! `cc.bug.govet_assign_to_self` — Go statement that assigns a binding
//! to itself: `x = x`, `s.field = s.field`, `arr[0] = arr[0]`.
//!
//! Mirrors `go vet` `assign`. Self-assignment is a no-op — the compiler
//! happily emits the dead store, but the human reader is told something
//! is happening when nothing is. Almost always a copy-paste bug where
//! one side was meant to reference a different variable / field /
//! index.
//!
//! Phase-11 source-byte detector: `.go` files only (excluding
//! `_test.go`). Match every line whose trimmed shape is
//! `<lhs> = <rhs>` (single `=`, not `:=` / `==`) where the trimmed LHS
//! and RHS strings are byte-equal AND the LHS is non-empty.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.govet_assign_to_self`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GovetAssignToSelfRule;

impl Rule for GovetAssignToSelfRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.govet_assign_to_self"
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
        "self-assignment `x = x` is a no-op (copy-paste bug)"
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
        if let Some(lhs) = parse_self_assign(line) {
            out.push(emit(path.clone(), idx + 1, line, lhs));
        }
    }
}

/// Return the LHS text when the line is a Go single-`=` assignment with
/// byte-equal LHS and RHS.
fn parse_self_assign(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let assign_idx = find_single_eq(trimmed)?;
    let lhs = trimmed[..assign_idx].trim();
    let rhs = trimmed[assign_idx + 1..]
        .trim()
        .trim_end_matches(';')
        .trim();
    if lhs.is_empty() || lhs.contains(',') {
        return None;
    }
    if lhs == rhs {
        return Some(lhs.to_owned());
    }
    None
}

/// Find a standalone `=` (not `:=`, `==`, `<=`, `>=`, `!=`, `+=`, `-=`,
/// `*=`, `/=`, `&=`, `|=`, `^=`, `%=`).
fn find_single_eq(trimmed: &str) -> Option<usize> {
    let bytes = trimmed.as_bytes();
    for (idx, b) in bytes.iter().enumerate() {
        if *b != b'=' {
            continue;
        }
        let prev = if idx > 0 { bytes[idx - 1] } else { b' ' };
        let next = bytes.get(idx + 1).copied().unwrap_or(b' ');
        if next == b'=' {
            continue;
        }
        if matches!(
            prev,
            b'=' | b'!'
                | b'<'
                | b'>'
                | b':'
                | b'+'
                | b'-'
                | b'*'
                | b'/'
                | b'&'
                | b'|'
                | b'^'
                | b'%'
        ) {
            continue;
        }
        return Some(idx);
    }
    None
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, lhs: String) -> Finding {
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
        rule_id: "cc.bug.govet_assign_to_self",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("self-assignment `{lhs} = {lhs}` is a no-op"),
        explanation: format!(
            "`{lhs} = {lhs}` writes the same value back to the same \
             location. The compiler is happy, but no state changes — \
             this is almost always a copy-paste bug where one side was \
             meant to reference a different binding, field, or index. \
             The reader has no way to tell whether the no-op is \
             intentional or a typo."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Inspect the surrounding code: which side was meant to \
             differ? Common shapes: `s.field = other.field`, \
             `arr[i] = arr[i+1]`, `dst = src`. If the assignment is \
             genuinely intentional (e.g. forcing a re-evaluation under \
             a custom setter), add a comment documenting why."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
