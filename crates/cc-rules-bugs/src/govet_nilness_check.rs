//! `cc.bug.govet_nilness_check` — Go path that checks `if x != nil`,
//! later assigns `x = nil`, then dereferences / passes `x` further down.
//!
//! Canonical bug:
//! ```go
//! if x != nil {
//!     // ...
//! }
//! x = nil
//! use(x.Field)            // <-- nil deref the static check just proved away
//! ```
//! The original `nil` check told the reader (and any taint tracker) that
//! `x` was non-nil. The intervening `x = nil` invalidates that proof,
//! and the trailing use crashes.
//!
//! OSS source: `go vet -nilness` (golang.org/x/tools/go/analysis/passes/nilness).
//!
//! Phase-12 source-byte heuristic: `.go` files only (skip `_test.go`).
//! For every `if <ident> != nil {` block, scan the rest of the
//! enclosing function for two ordered events on the same identifier:
//! (1) `<ident> = nil` and (2) a later `<ident>.<field>` /
//! `<ident>(...)` / `*<ident>` use. Emit on the use line.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.govet_nilness_check`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GovetNilnessCheckRule;

/// Maximum lookahead from an `if x != nil` block — beyond this the
/// static-analysis hop is too speculative to flag.
const SCAN_WINDOW: usize = 40;

impl Rule for GovetNilnessCheckRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.govet_nilness_check"
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
        "post-nil-check use of a variable later reassigned to nil"
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
    let lines: Vec<&str> = text.lines().collect();
    for idx in 0..lines.len() {
        let Some(name) = parse_nil_check(lines[idx]) else {
            continue;
        };
        if let Some(rel) = find_use_after_nil_assign(&lines, idx, &name) {
            let line_no = idx + rel + 1;
            out.push(emit(path.clone(), line_no, lines[idx + rel], &name));
        }
    }
}

/// Return the identifier `<x>` from a leading `if <x> != nil {` line.
fn parse_nil_check(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("if ")?;
    let (lhs, after) = rest.split_once("!=")?;
    let lhs_name = lhs.trim();
    if !is_simple_ident(lhs_name) {
        return None;
    }
    let after = after.trim_start();
    if !after.starts_with("nil") {
        return None;
    }
    Some(lhs_name.to_owned())
}

fn is_simple_ident(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !s.as_bytes()[0].is_ascii_digit()
}

/// Walk forward from `start_idx` for [`SCAN_WINDOW`] lines. Track whether
/// `<name> = nil` has been seen. Emit on the first subsequent line that
/// uses `<name>` in a deref or call context.
fn find_use_after_nil_assign(lines: &[&str], start_idx: usize, name: &str) -> Option<usize> {
    let end = (start_idx + 1 + SCAN_WINDOW).min(lines.len());
    let mut nil_assigned = false;
    let nil_assign = format!("{name} = nil");
    for rel in 1..end - start_idx {
        let line = lines[start_idx + rel];
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if !nil_assigned && line_contains_assign(trimmed, &nil_assign) {
            nil_assigned = true;
            continue;
        }
        if nil_assigned && line_uses_var(trimmed, name) {
            return Some(rel);
        }
    }
    None
}

fn line_contains_assign(trimmed: &str, needle: &str) -> bool {
    trimmed.starts_with(needle)
        || trimmed.contains(&format!("\t{needle}"))
        || trimmed.contains(&format!(" {needle}"))
}

/// True iff `line` uses `<name>` as a deref / call / index target —
/// `name.field`, `name(`, `*name`, `name[`. We deliberately skip bare
/// `name = ...` reassignment.
fn line_uses_var(trimmed: &str, name: &str) -> bool {
    for shape in [
        format!("{name}."),
        format!("{name}("),
        format!("*{name}"),
        format!("{name}["),
    ] {
        if trimmed.contains(&shape) {
            return true;
        }
    }
    false
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, name: &str) -> Finding {
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
        rule_id: "cc.bug.govet_nilness_check",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("post-nil-check use of `{name}` after intervening `{name} = nil`"),
        explanation: format!(
            "An earlier `if {name} != nil` branch told the reader and \
             every static checker that `{name}` was non-nil on this \
             path. A subsequent `{name} = nil` assignment invalidates \
             that proof, but this line dereferences / calls / indexes \
             `{name}` anyway. The original guard is now misleading and \
             this access will panic if reached."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Either re-check `if x != nil` immediately before the use, \
             or restructure so the nil-assign cannot precede the deref. \
             A common cleanup: assign-to-nil only at the end of a \
             function so the value is unreachable afterwards."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
