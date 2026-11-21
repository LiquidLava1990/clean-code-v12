//! `cc.taint.gosec_unsafe_pointer_use` — Go `unsafe.Pointer(...)`.
//!
//! Mirrors [gosec G103] (`Audit the use of unsafe block`). Go's
//! `unsafe.Pointer` opts out of the type system: it can violate
//! memory-safety, race-detector invariants, and GC assumptions all at
//! once. Every legitimate use is *technically* possible to write
//! safely, but each call site is high-risk and merits an explicit
//! review — gosec flags every occurrence.
//!
//! Detection: source-byte scan for `unsafe.Pointer(` in `.go` files.
//!
//! [gosec G103]: https://github.com/securego/gosec/blob/master/rules/unsafe.go

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TaintFindingBlueprint,
};

const NEEDLE: &str = "unsafe.Pointer(";

/// Family-4 probe `cc.taint.gosec_unsafe_pointer_use`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecUnsafePointerUseRule;

impl Rule for GosecUnsafePointerUseRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.gosec_unsafe_pointer_use"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Taint
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "Go unsafe.Pointer(...) call (gosec G103)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_go_source(&path) {
                continue;
            }
            if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
                continue;
            }
            scan_file(ctx, &path, &mut out);
        }
        out
    }
}

fn is_go_source(path: &Utf8PathBuf) -> bool {
    let ext_ok = path.extension().map(str::to_ascii_lowercase).as_deref() == Some("go");
    if !ext_ok {
        return false;
    }
    !path
        .file_name()
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
        if line.contains(NEEDLE) && !is_comment_line(line) {
            out.push(emit(path.clone(), idx + 1, line));
        }
    }
}

fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(TaintFindingBlueprint {
        rule_id: "cc.taint.gosec_unsafe_pointer_use",
        category: cc_finding::Category::Taint,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "`unsafe.Pointer(...)` opts out of Go's type system (gosec G103)".into(),
        explanation: "`unsafe.Pointer` lets you cast between arbitrary \
             pointer types and invent integers as addresses. It bypasses \
             the type system, the GC's tracking model, and the race \
             detector's invariants. gosec G103 flags every occurrence so \
             reviewers can confirm each one is necessary, sound, and \
             documented."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Audit each call: confirm the pointer arithmetic obeys the \
             rules in `unsafe.Pointer`'s godoc, document why the safe \
             API is insufficient, and consider isolating the unsafe \
             block behind a tested wrapper."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
