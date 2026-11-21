//! `cc.bug.dead_thread` — `new Thread(...)` whose result is bound to a
//! variable but `.start()` is never called on that variable.
//!
//! A `Thread` instance does nothing until `start()` is invoked. Code
//! like `Thread t = new Thread(r);` followed by no `t.start()` quietly
//! drops the runnable on the floor — the work the author intended to
//! schedule never runs.
//!
//! OSS source: Error Prone `DeadThread` bug pattern.
//!
//! Phase-8 source-byte heuristic (`.java` / `.kt` only): the kernel
//! has no first-class Java / Kotlin frontend yet, so this probe scans
//! raw source. For each binding of the form `Thread <name> = new
//! Thread(` we look for a subsequent `<name>.start(` line within a
//! 200-line window. Absent ⇒ finding.
//!
//! Confidence 0.85 — the heuristic misses cases where `start` is
//! invoked through a helper method or escapes the file.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-DEAD-THREAD.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeadThreadRule;

/// Window we scan after a `Thread t = new Thread(` for a `t.start(` call.
const SEARCH_WINDOW_LINES: usize = 200;

impl Rule for DeadThreadRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.dead_thread"
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
        "Thread instance is constructed but never started"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_supported_extension(&path) {
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

fn is_supported_extension(path: &Utf8PathBuf) -> bool {
    matches!(path.extension(), Some("java") | Some("kt") | Some("kts"))
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
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        let Some(name) = extract_thread_binding(trimmed) else {
            continue;
        };
        if started_in_window(&lines, idx, name) {
            continue;
        }
        out.push(emit(path.clone(), idx + 1, line, name));
    }
}

/// Pull `<name>` out of `Thread <name> = new Thread(...)` (Java) or
/// `val <name> = Thread(...)` (Kotlin). Returns `None` for any other
/// shape.
fn extract_thread_binding(trimmed: &str) -> Option<&str> {
    if let Some(rest) = trimmed.strip_prefix("Thread ") {
        return parse_java_binding(rest);
    }
    if let Some(rest) = trimmed
        .strip_prefix("val ")
        .or_else(|| trimmed.strip_prefix("var "))
    {
        return parse_kotlin_binding(rest);
    }
    None
}

fn parse_java_binding(rest: &str) -> Option<&str> {
    let eq = rest.find('=')?;
    let name = rest[..eq].trim();
    let after = rest[eq + 1..].trim_start();
    if !after.starts_with("new Thread(") {
        return None;
    }
    if name.is_empty() || !is_simple_ident(name) {
        return None;
    }
    Some(name)
}

fn parse_kotlin_binding(rest: &str) -> Option<&str> {
    let eq = rest.find('=')?;
    let name = rest[..eq].trim().split(':').next()?.trim();
    let after = rest[eq + 1..].trim_start();
    if !after.starts_with("Thread(") {
        return None;
    }
    if name.is_empty() || !is_simple_ident(name) {
        return None;
    }
    Some(name)
}

fn is_simple_ident(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

fn started_in_window(lines: &[&str], start_idx: usize, name: &str) -> bool {
    let needle = format!("{name}.start(");
    let end = (start_idx + SEARCH_WINDOW_LINES).min(lines.len());
    lines[start_idx + 1..end]
        .iter()
        .any(|l| l.contains(&needle))
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, name: &str) -> Finding {
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
        rule_id: "cc.bug.dead_thread",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("Thread `{name}` is constructed but never started"),
        explanation: format!(
            "Variable `{name}` holds a freshly-constructed `Thread`, but \
             no `{name}.start()` is reachable in this file. Threads do \
             nothing until `start()` is invoked, so the runnable passed \
             to the constructor is silently dropped — the work the author \
             intended to schedule never runs."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Call `.start()` on the thread immediately after \
             construction, or — if a thread is the wrong tool — submit \
             the `Runnable` to an `ExecutorService` so the executor \
             owns the lifecycle."
                .into(),
        ),
        snippet,
        weight: 3,
    })
}
