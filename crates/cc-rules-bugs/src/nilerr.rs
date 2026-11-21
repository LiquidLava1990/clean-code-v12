//! `cc.bug.nilerr` — Go branch that checks `if err != nil` then
//! returns `nil` (or a non-error value) instead of propagating `err`.
//!
//! The canonical bug:
//! ```go
//! if err != nil {
//!     return nil          // <-- swallowed
//! }
//! ```
//! The caller sees a successful return and operates on a zero-valued
//! result that came from a known-failed path. This is the most
//! corrosive class of error-handling bug: every layer above the
//! offender is convinced the operation succeeded.
//!
//! OSS source: golangci `nilerr`.
//!
//! Phase-9 source-byte heuristic: `.go` files only. Detect `if err !=
//! nil {` followed (within ~6 lines) by a `return nil` whose body
//! does NOT mention `err`. Skip `_test.go` for safety.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    apply_braces, build_finding, is_go_test_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-NILERR.
#[derive(Debug, Default, Clone, Copy)]
pub struct NilerrRule;

const NIL_CHECK: &str = "if err != nil";
/// Lookahead window — `nilerr` short blocks rarely exceed five lines.
const LOOKAHEAD: usize = 6;

impl Rule for NilerrRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.nilerr"
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
        "if err != nil { return nil } silently swallows a real error"
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
        if !is_err_check(lines[idx]) {
            continue;
        }
        let block_end = (idx + LOOKAHEAD).min(lines.len());
        let block = &lines[idx + 1..block_end];
        if let Some(rel) = find_nil_swallowing_return(block) {
            out.push(emit(path.clone(), idx + 1 + rel + 1, lines[idx + 1 + rel]));
        }
    }
}

fn is_err_check(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with(NIL_CHECK) && trimmed.ends_with('{')
}

/// Find a `return nil` (or `return nil, nil`) line in `block` whose
/// content does NOT mention `err`. Returns the relative index. Stops
/// at the closing `}` of the if-block.
fn find_nil_swallowing_return(block: &[&str]) -> Option<usize> {
    let mut depth: i32 = 1; // we're already inside the `if {` block
    for (rel, line) in block.iter().enumerate() {
        depth = apply_braces(depth, line);
        if depth <= 0 {
            return None;
        }
        let trimmed = line.trim_start();
        if !trimmed.starts_with("return") {
            continue;
        }
        if trimmed.contains("err") {
            continue;
        }
        if returns_only_nil(trimmed) {
            return Some(rel);
        }
    }
    None
}

/// True for `return nil`, `return nil, nil`, `return nil, nil, nil`,
/// or `return _ , nil`. Conservative — single non-nil token disqualifies.
fn returns_only_nil(trimmed: &str) -> bool {
    let after = match trimmed.strip_prefix("return") {
        Some(s) => s.trim(),
        None => return false,
    };
    if after.is_empty() {
        return false;
    }
    after
        .split(',')
        .map(str::trim)
        .all(|tok| tok == "nil" || tok == "_")
        && after.contains("nil")
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
        rule_id: "cc.bug.nilerr",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: "`if err != nil { return nil }` silently swallows the error".into(),
        explanation: "The branch knows an error occurred (`err != nil`) but \
             returns `nil` to the caller. Every layer above this \
             function then operates on a zero value as if the call \
             succeeded. This is the most corrosive class of \
             error-handling bug: failures vanish without a trace and \
             debugging starts at the symptom, miles from the source."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Return `err` (or wrap it: `fmt.Errorf(\"context: %w\", err)`) \
             instead of `nil`. If the caller genuinely should treat this \
             error as a no-op, document the intent and return a sentinel \
             like `errors.Is(err, sql.ErrNoRows)` -> nil — explicit, \
             greppable, and reviewable."
                .into(),
        ),
        snippet,
        weight: 5,
    })
}
