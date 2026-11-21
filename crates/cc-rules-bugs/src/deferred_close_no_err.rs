//! `cc.bug.deferred_close_no_err` — Go `defer x.Close()` where `Close()`
//! returns an `error` and the error is silently dropped.
//!
//! Common offenders:
//!
//! - `defer file.Close()` for `*os.File`
//! - `defer resp.Body.Close()` for `*http.Response.Body`
//! - `defer rows.Close()` for `*sql.Rows`
//! - `defer tx.Rollback()` for `*sql.Tx`
//!
//! All of these can fail (sync error, network reset, transaction
//! conflict), and dropping the error means data loss is invisible. The
//! idiomatic fix is to wrap the deferred call in a closure that captures
//! and surfaces the error.
//!
//! Phase-7 source-byte heuristic: `.go` files only. Detect lines
//! starting with `defer ` whose receiver matches a known err-returning
//! resource and whose right-hand side is a bare method call.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-DEFERRED-CLOSE-NO-ERR.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeferredCloseNoErrRule;

/// Methods on err-returning resources. Closed list — extend on contact.
const ERR_RETURNING_METHODS: &[&str] = &[
    ".Close()",
    ".Body.Close()",
    ".Rollback()",
    ".Commit()",
    ".Sync()",
];

impl Rule for DeferredCloseNoErrRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.deferred_close_no_err"
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
        "deferred call to an err-returning method silently drops the error"
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
    for (line_idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("defer ") {
            continue;
        }
        if let Some(method) = ERR_RETURNING_METHODS.iter().find(|m| trimmed.contains(*m)) {
            out.push(emit(path.clone(), line_idx + 1, line, method));
        }
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, method: &str) -> Finding {
    let pos = Position::new(line_no as u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.deferred_close_no_err",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("deferred `{}` discards a returned error", method.trim()),
        explanation: format!(
            "`defer {}` runs the call but throws away the returned `error`. \
             For `Close` / `Sync` / `Commit` / `Rollback`, that error is \
             load-bearing — sync failure means data was buffered but never \
             written, transaction failure means the database state is not \
             what the code thinks it is. Silent failure here is data loss.",
            method.trim()
        ),
        remediation: Remediation::SuggestedRewrite(
            "Wrap the deferred call in a closure that captures + surfaces \
             the error: `defer func() { if err := x.Close(); err != nil { \
             // log or assign to outer named return } }()`. For test code \
             that genuinely doesn't care, suppress with `// nolint:errcheck`."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
