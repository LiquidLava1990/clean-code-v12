//! `cc.taint.gosec_command_injection_exec` — Go `exec.Command(...)` /
//! `exec.CommandContext(ctx, ...)` whose first program argument is not
//! a string literal.
//!
//! Mirrors [gosec G204] (`Subprocess launching with variable`). The
//! existing [`crate::command_injection`] probe catches AST-level
//! taint flow into shell-exec sinks. This probe is the syntactic
//! Go-only fallback that fires whenever the first argument to
//! `exec.Command` / `exec.CommandContext` is anything other than a
//! quoted string literal — variable, expression, or `+`-concat.
//!
//! [gosec G204]: https://github.com/securego/gosec/blob/master/rules/subproc.go

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::_go_syntax::{contains_unquoted_plus, first_arg_slice};
use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TaintFindingBlueprint,
};

/// Family-4 probe `cc.taint.gosec_command_injection_exec`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GosecCommandInjectionExecRule;

impl Rule for GosecCommandInjectionExecRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.gosec_command_injection_exec"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Taint
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "Go exec.Command first arg is not a string literal (gosec G204)"
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
        for sink in find_unsafe_exec_sinks(line) {
            out.push(emit(path.clone(), idx + 1, line, sink));
        }
    }
}

/// Return the matched sink name(s) on this line whose program argument
/// is *not* a string literal. Both `exec.Command(` and
/// `exec.CommandContext(` are inspected.
fn find_unsafe_exec_sinks(line: &str) -> Vec<&'static str> {
    let mut hits = Vec::new();
    if let Some(arg) = first_arg_after(line, "exec.Command(") {
        if !is_string_literal_first_arg(&arg) {
            hits.push("exec.Command");
        }
    }
    if let Some(arg) = first_arg_after_second_arg(line, "exec.CommandContext(") {
        if !is_string_literal_first_arg(&arg) {
            hits.push("exec.CommandContext");
        }
    }
    hits
}

fn first_arg_after(line: &str, needle: &str) -> Option<String> {
    let pos = line.find(needle)?;
    let after = &line[pos + needle.len()..];
    Some(first_arg_slice(after).to_owned())
}

/// `exec.CommandContext(ctx, name, ...)` — skip the first arg (`ctx`)
/// and return the second (`name`).
fn first_arg_after_second_arg(line: &str, needle: &str) -> Option<String> {
    let pos = line.find(needle)?;
    let after = &line[pos + needle.len()..];
    let mut remaining = after;
    let _first = first_arg_slice(remaining);
    let advance = _first.len();
    if advance + 1 > remaining.len() {
        return None;
    }
    remaining = &remaining[advance..];
    let comma = remaining.find(',')?;
    let next = &remaining[comma + 1..];
    Some(first_arg_slice(next).to_owned())
}

/// True iff the trimmed `arg` begins with `"` AND ends with `"` AND
/// contains no `+` outside the quotes — i.e. a single bare string
/// literal. A backtick-quoted Go raw string is also accepted.
fn is_string_literal_first_arg(arg: &str) -> bool {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return false;
    }
    let first = trimmed.chars().next().unwrap_or(' ');
    let last = trimmed.chars().last().unwrap_or(' ');
    let bracketed = (first == '"' && last == '"') || (first == '`' && last == '`');
    if !bracketed {
        return false;
    }
    !contains_unquoted_plus(trimmed)
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, sink: &str) -> Finding {
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
        rule_id: "cc.taint.gosec_command_injection_exec",
        category: cc_finding::Category::Taint,
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("`{sink}` called with a non-literal program name (gosec G204)"),
        explanation: "The first argument to `exec.Command` / \
             `exec.CommandContext` controls *which binary* is launched. \
             A non-literal program name lets any value reaching it (env \
             variable, request data, CLI argv, concatenated string) \
             choose the executable. gosec G204 flags this exact pattern."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Pass the program path as a string literal and put user \
             input into subsequent argv elements (which Go forwards \
             without shell expansion). If the binary really must be \
             dynamic, look it up in an allow-list keyed mapping."
                .into(),
        ),
        snippet,
        weight: 7,
    })
}
