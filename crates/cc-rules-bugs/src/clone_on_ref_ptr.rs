//! `cc.bug.clone_on_ref_ptr` — `.clone()` on an `Arc<T>` / `Rc<T>`
//! receiver instead of the explicit `Arc::clone(&x)` / `Rc::clone(&x)`.
//!
//! Canonical bug:
//! ```text
//! let counter = Arc::new(AtomicU32::new(0));
//! let worker = counter.clone();          // looks like a deep copy
//! ```
//! `.clone()` on an `Arc`/`Rc` is a refcount bump — fast, allocation-free.
//! But the call site reads exactly like a deep clone of `T`, which can
//! be enormously expensive. The associated form `Arc::clone(&counter)`
//! makes the intent explicit at the point of call so reviewers don't
//! have to look up the receiver type to know whether the line allocates.
//!
//! OSS source: clippy `clone_on_ref_ptr`.
//!
//! Phase-10 source-byte heuristic: scan `.rs` files. When a function
//! body declares `let <ident> = Arc::new(...)` (or `Rc::new(...)`),
//! flag any subsequent `<ident>.clone()` in the same function. Skip
//! test files and rule-pack source.
//!
//! Severity `Nit`, confidence 0.85.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-CLONE-ON-REF-PTR.
#[derive(Debug, Default, Clone, Copy)]
pub struct CloneOnRefPtrRule;

const REF_PTR_CTORS: &[(&str, &str)] = &[
    ("Arc::new(", "Arc"),
    ("Rc::new(", "Rc"),
    ("std::sync::Arc::new(", "Arc"),
    ("std::rc::Rc::new(", "Rc"),
];

impl Rule for CloneOnRefPtrRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.clone_on_ref_ptr"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "`x.clone()` on an Arc/Rc receiver hides whether the line allocates"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("rs") {
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

fn scan_file(ctx: &RuleContext<'_>, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let lines: Vec<&str> = text.lines().collect();
    let bindings = collect_arc_rc_bindings(&lines);
    if bindings.is_empty() {
        return;
    }
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        for (name, ptr_kind) in &bindings {
            if line_calls_clone_on(line, name) {
                out.push(emit(path.clone(), idx + 1, line, name, ptr_kind));
            }
        }
    }
}

/// Collect `(binding_name, ptr_kind)` for every `let <name> = Arc::new(...)` /
/// `Rc::new(...)` assignment seen at any depth in the file.
fn collect_arc_rc_bindings(lines: &[&str]) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for line in lines {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("let ") {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("let ") else {
            continue;
        };
        let rest = rest.strip_prefix("mut ").unwrap_or(rest);
        let Some(eq_idx) = rest.find('=') else {
            continue;
        };
        let lhs = rest[..eq_idx].trim().trim_end_matches(':');
        let rhs = rest[eq_idx + 1..].trim_start();
        let Some(name) = extract_simple_binding(lhs) else {
            continue;
        };
        for (ctor, kind) in REF_PTR_CTORS {
            if rhs.starts_with(ctor) {
                out.push((name.to_owned(), kind));
                break;
            }
        }
    }
    out
}

/// Strip a `: <type>` annotation and return the leading identifier
/// when the LHS is a plain `<ident>` (we skip destructured patterns).
fn extract_simple_binding(lhs: &str) -> Option<&str> {
    let core = lhs.split(':').next()?.trim();
    if core.is_empty() {
        return None;
    }
    if !core.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(core)
}

fn line_calls_clone_on(line: &str, name: &str) -> bool {
    let needle = format!("{name}.clone()");
    let Some(idx) = line.find(&needle) else {
        return false;
    };
    // Reject `<bigger_name>.clone()` — verify the byte before is a non-ident.
    if idx > 0 {
        let prev = line.as_bytes()[idx - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
            return false;
        }
    }
    true
}

fn emit(
    path: Utf8PathBuf,
    line_no: usize,
    line: &str,
    name: &str,
    ptr_kind: &'static str,
) -> Finding {
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
        rule_id: "cc.bug.clone_on_ref_ptr",
        severity: Severity::Nit,
        confidence: Confidence::new(0.85),
        location,
        headline: format!(
            "`{name}.clone()` on an `{ptr_kind}` reads as a deep clone — \
             prefer `{ptr_kind}::clone(&{name})`"
        ),
        explanation: format!(
            "`.clone()` on an `{ptr_kind}<T>` is a refcount bump — \
             O(1), allocation-free. But the syntax is identical to a \
             deep clone of `T`, which may be megabytes. Reviewers \
             have to look up the receiver type to know whether the \
             line allocates. The associated form \
             `{ptr_kind}::clone(&{name})` is the same machine code \
             with the intent on the surface."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace `{name}.clone()` with `{ptr_kind}::clone(\
                 &{name})`. Refcount semantics are unchanged; the \
                 difference is solely readability at the call site."
        )),
        snippet,
        weight: 1,
    })
}
