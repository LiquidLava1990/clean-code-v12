//! `cc.bug.govet_lostcancel` — Go context-cancellation function
//! discarded into `_`.
//!
//! ```go
//! ctx, _ := context.WithCancel(parent)        // <-- cancel lost
//! ctx, _ := context.WithTimeout(parent, 5*s)
//! ctx, _ := context.WithDeadline(parent, t)
//! ```
//!
//! Mirrors `go vet` `lostcancel`. Discarding the cancel func leaks the
//! context: the goroutine spawned by the timeout / deadline / cancel
//! plumbing is never released and the parent context never observes the
//! child's completion.
//!
//! Phase-11 source-byte detector: `.go` files only (excluding
//! `_test.go`). Match every line whose trimmed shape is
//! `_, _ := context.With...(...)` or `_, _ = context.With...(...)` or
//! `something, _ := context.With...(...)` (only the cancel slot is
//! discarded — first slot can be any binding).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.govet_lostcancel`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GovetLostcancelRule;

const CTX_FACTORIES: &[&str] = &[
    "context.WithCancel(",
    "context.WithCancelCause(",
    "context.WithTimeout(",
    "context.WithTimeoutCause(",
    "context.WithDeadline(",
    "context.WithDeadlineCause(",
];

impl Rule for GovetLostcancelRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.govet_lostcancel"
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
        "context cancel function discarded — leaks goroutine + context"
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
        if matches_lost_cancel(line) {
            out.push(emit(path.clone(), idx + 1, line));
        }
    }
}

fn matches_lost_cancel(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return false;
    }
    let Some(assign_idx) = find_assign_op(trimmed) else {
        return false;
    };
    let lhs = trimmed[..assign_idx].trim_end();
    if !cancel_slot_is_underscore(lhs) {
        return false;
    }
    let rhs = trimmed[assign_idx..].trim_start();
    let rhs = rhs
        .trim_start_matches(":=")
        .trim_start_matches('=')
        .trim_start();
    CTX_FACTORIES.iter().any(|f| rhs.starts_with(f))
}

fn find_assign_op(trimmed: &str) -> Option<usize> {
    if let Some(idx) = trimmed.find(":=") {
        return Some(idx);
    }
    // Plain `=` is allowed too (re-assign of an existing pair). Avoid
    // `==` / `!=` / `<=` / `>=` matches.
    let bytes = trimmed.as_bytes();
    for (idx, b) in bytes.iter().enumerate() {
        if *b != b'=' {
            continue;
        }
        let prev = if idx > 0 { bytes[idx - 1] } else { b' ' };
        let next = bytes.get(idx + 1).copied().unwrap_or(b' ');
        if prev == b'=' || prev == b'!' || prev == b'<' || prev == b'>' || next == b'=' {
            continue;
        }
        return Some(idx);
    }
    None
}

/// True iff `lhs` is exactly `<binding>, _` — first slot is any
/// identifier (or `_`), second slot is the discarded cancel.
fn cancel_slot_is_underscore(lhs: &str) -> bool {
    let parts: Vec<&str> = lhs.split(',').map(str::trim).collect();
    if parts.len() != 2 {
        return false;
    }
    parts[1] == "_" && !parts[0].is_empty()
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
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
        rule_id: "cc.bug.govet_lostcancel",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "context cancel function discarded into `_`".into(),
        explanation: "`context.WithCancel` / `WithTimeout` / `WithDeadline` \
             return both a derived context and a cancel function. The \
             contract is explicit: the caller MUST call `cancel()` to \
             release the timer goroutine and the parent context's \
             reference to the child. Discarding the cancel func into \
             `_` leaks a goroutine for every call on a hot path."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Bind the cancel func and call it: \
             `ctx, cancel := context.WithCancel(parent); defer cancel()`. \
             For long-lived contexts that must outlive the surrounding \
             function, store the cancel func somewhere the owning \
             goroutine can reach and call it on shutdown."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
