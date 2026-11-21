//! `cc.bug.govet_copylocks` — Go copy of a value containing a
//! `sync.Mutex` / `sync.RWMutex` / `sync.WaitGroup`. The Go runtime
//! semantics are that locks are non-copyable: copying creates two
//! independent locks that no longer mediate the shared state.
//!
//! Mirrors `go vet` `copylocks`. The motivation: silent concurrency
//! bugs. The compiler will not stop you from `n := m` where `m` is a
//! `sync.Mutex`; you only find out at runtime when the lock fails to
//! exclude.
//!
//! Phase-11 source-byte detector: `.go` files only (excluding
//! `_test.go`). Track local declarations with mutex-bearing types
//! (`var m sync.Mutex` / `m := sync.Mutex{}`), then flag any
//! subsequent line that copies the value (`n := m` / `n = m` /
//! `f(m)` where `f` takes by value).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_go_test_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.govet_copylocks`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GovetCopylocksRule;

const LOCK_TYPE_NEEDLES: &[&str] = &[
    "sync.Mutex",
    "sync.RWMutex",
    "sync.WaitGroup",
    "sync.Cond",
    "sync.Once",
];

impl Rule for GovetCopylocksRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.govet_copylocks"
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
        "copying a `sync.Mutex` value detaches the lock from its state"
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
    let lock_bindings = collect_lock_bindings(&lines);
    if lock_bindings.is_empty() {
        return;
    }
    for (idx, line) in lines.iter().enumerate() {
        if let Some(name) = find_copy_of(line, &lock_bindings) {
            out.push(emit(path.clone(), idx + 1, line, name));
        }
    }
}

/// Collect every binding declared as one of the [`LOCK_TYPE_NEEDLES`]
/// types in this file. Conservative: walks `var NAME TYPE` and
/// `NAME := TYPE{}` shapes. Returns the binding names.
fn collect_lock_bindings(lines: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in lines {
        let trimmed = line.trim_start();
        if let Some(name) = parse_var_decl(trimmed) {
            out.push(name);
            continue;
        }
        if let Some(name) = parse_short_decl(trimmed) {
            out.push(name);
        }
    }
    out
}

/// Parse `var NAME sync.Mutex` (no initializer / value initializer).
fn parse_var_decl(trimmed: &str) -> Option<String> {
    let after = trimmed.strip_prefix("var ")?.trim_start();
    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    let rest = after[name.len()..].trim_start();
    if LOCK_TYPE_NEEDLES.iter().any(|t| rest.starts_with(t)) {
        Some(name)
    } else {
        None
    }
}

/// Parse `NAME := sync.Mutex{}` (or any short decl whose RHS looks like
/// a lock-type literal).
fn parse_short_decl(trimmed: &str) -> Option<String> {
    let assign_idx = trimmed.find(":=")?;
    let lhs = trimmed[..assign_idx].trim();
    if lhs.contains(',') {
        return None;
    }
    let name: String = lhs
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() || name != lhs {
        return None;
    }
    let rhs = trimmed[assign_idx + 2..].trim_start();
    if LOCK_TYPE_NEEDLES.iter().any(|t| rhs.starts_with(t)) {
        Some(name)
    } else {
        None
    }
}

/// True iff `line` copies one of `bindings` by-value.
/// Shapes: `n := <name>` / `n = <name>` (no `&` / no `.` continuation).
fn find_copy_of<'a>(line: &str, bindings: &'a [String]) -> Option<&'a str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let assign_idx = trimmed.find(":=").or_else(|| {
        trimmed
            .find('=')
            .filter(|&i| trimmed.as_bytes().get(i + 1).copied() != Some(b'='))
    })?;
    let after = trimmed[assign_idx..].trim_start();
    let after = after
        .trim_start_matches(":=")
        .trim_start_matches('=')
        .trim_start();
    if after.starts_with('&') {
        return None;
    }
    for binding in bindings {
        if rhs_is_bare_binding(after, binding) {
            return Some(binding.as_str());
        }
    }
    None
}

fn rhs_is_bare_binding(after: &str, binding: &str) -> bool {
    if !after.starts_with(binding) {
        return false;
    }
    let next = after.as_bytes().get(binding.len()).copied();
    matches!(
        next,
        None | Some(b' ') | Some(b'\t') | Some(b';') | Some(b',')
    )
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, binding: &str) -> Finding {
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
        rule_id: "cc.bug.govet_copylocks",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("copy of lock-bearing value `{binding}`"),
        explanation: format!(
            "`{binding}` carries a `sync.Mutex` / `sync.WaitGroup` / \
             other non-copyable lock type. Copying the value creates a \
             second independent lock that does not mediate the same \
             state — concurrent users of the original and the copy will \
             race. The Go runtime cannot warn at compile time; this is a \
             silent correctness bug discovered only when contention \
             produces inconsistent state."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Pass `&{binding}` (a pointer) instead of the value itself. \
             For struct types containing a lock, embed the mutex by \
             value and pass the struct by pointer (`*MyStruct`) \
             everywhere. Lock types must never be copied — make this \
             explicit in the API."
        )),
        snippet,
        weight: 4,
    })
}
