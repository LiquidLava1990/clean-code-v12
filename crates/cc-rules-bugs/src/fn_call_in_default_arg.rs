//! `cc.bug.fn_call_in_default_arg` — Python `def f(x=time.time())` /
//! `def f(x=os.getcwd())`. Non-literal default args are evaluated once
//! at function-definition time, freezing whatever the call returned at
//! import time and silently using that frozen value across every call.
//!
//! Mirrors ruff `B008` (function-call-in-default-argument).
//!
//! Phase-9 detector: scan every Python file once for `def NAME(` lines
//! containing a parameter default that looks like a function call.
//! Whitelist the standard idiomatic exceptions (`field(...)`, `Field(...)`,
//! `fastapi.Depends(...)`, `Query(...)`, `Body(...)`, `Header(...)`,
//! `Cookie(...)`, `Path(...)`, `File(...)`, `Form(...)` from FastAPI /
//! pydantic / dataclasses).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.fn_call_in_default_arg`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FnCallInDefaultArgRule;

/// Idiomatic exceptions that ruff B008 also whitelists. Lowercased
/// before comparison.
const ALLOWED_CALLEES: &[&str] = &[
    "field",
    "depends",
    "query",
    "body",
    "header",
    "cookie",
    "path",
    "file",
    "form",
    "security",
    "websocket",
];

impl Rule for FnCallInDefaultArgRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.fn_call_in_default_arg"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "Python function parameter with a function-call default value"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("py") {
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
        if !trimmed.starts_with("def ") && !trimmed.starts_with("async def ") {
            continue;
        }
        if let Some(callee) = find_call_default(line) {
            out.push(emit(path.clone(), line_idx + 1, line, callee));
        }
    }
}

/// Locate the first `=<callee>(` segment inside the parameter list.
fn find_call_default(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let open = line.find('(')?;
    let mut depth: i32 = 1;
    let mut idx = open + 1;
    while idx < bytes.len() && depth > 0 {
        update_depth(bytes[idx], &mut depth);
        if is_top_level_assign(bytes, idx, depth) {
            if let Some(callee) = check_default(&line[idx + 1..]) {
                return Some(callee);
            }
        }
        idx += 1;
    }
    None
}

fn update_depth(byte: u8, depth: &mut i32) {
    match byte {
        b'(' | b'[' | b'{' => *depth += 1,
        b')' | b']' | b'}' => *depth -= 1,
        _ => {}
    }
}

fn is_top_level_assign(bytes: &[u8], idx: usize, depth: i32) -> bool {
    bytes[idx] == b'=' && depth == 1 && bytes.get(idx + 1).copied() != Some(b'=')
}

fn check_default(rest: &str) -> Option<String> {
    let after = rest.trim_start();
    let callee = match_call(after)?;
    if is_allowed(&callee) {
        return None;
    }
    Some(callee)
}

/// If `after_eq` looks like `Name(...)` or `mod.Name(...)`, return the
/// dotted callee text.
fn match_call(after_eq: &str) -> Option<String> {
    let mut end = 0usize;
    for (idx, ch) in after_eq.char_indices() {
        if ch.is_alphanumeric() || ch == '_' || ch == '.' {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    let callee = &after_eq[..end];
    if callee.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let rest = &after_eq[end..];
    if !rest.starts_with('(') {
        return None;
    }
    Some(callee.to_owned())
}

fn is_allowed(callee: &str) -> bool {
    let last = callee
        .rsplit('.')
        .next()
        .unwrap_or(callee)
        .to_ascii_lowercase();
    ALLOWED_CALLEES.iter().any(|name| *name == last)
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, callee: String) -> Finding {
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
        rule_id: "cc.bug.fn_call_in_default_arg",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("default value `{callee}(...)` evaluated once at def-time"),
        explanation: format!(
            "Python evaluates default arguments exactly once, when the \
             `def` runs — not on every call. `{callee}(...)` therefore \
             freezes whatever value the call returned at import time \
             and quietly reuses it forever. Time-sensitive callees \
             (`time.time()`, `datetime.now()`, `uuid.uuid4()`, `os.getcwd()`) \
             produce stale data; mutable returns leak state across calls."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Default the parameter to `None` and call inside the body: \
             `def f(x: T | None = None): x = {callee}(...) if x is None \
             else x`. The call now runs per invocation."
        )),
        snippet,
        weight: 3,
    })
}
