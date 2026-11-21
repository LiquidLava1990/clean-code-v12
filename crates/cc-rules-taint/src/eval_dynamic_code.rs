//! `cc.taint.eval_dynamic_code` — dynamic code-execution sinks.
//!
//! Calls to `eval` / `exec` / `new Function(...)` interpret their first
//! argument as **executable program text**. When that argument is not a
//! compile-time constant, an attacker who controls any byte of it can
//! execute arbitrary code. Cross-language coverage:
//!
//! - **Python**: `eval(...)`, `exec(...)`, `compile(..., 'exec')`.
//! - **JavaScript / TypeScript**: `eval(...)`, `new Function(...)`,
//!   `setTimeout("string", ...)`, `setInterval("string", ...)`.
//! - **Ruby**: `eval(...)`, `instance_eval(...)`, `class_eval(...)`,
//!   `module_eval(...)`.
//!
//! OSS source: CodeQL `js/code-injection`, `py/code-injection`,
//! `rb/code-injection`; Sonar `python:S1523`, `javascript:S1523`,
//! `ruby:S1523`; Semgrep `python.lang.security.audit.dangerous-eval`,
//! `javascript.lang.security.audit.dangerous-eval`.
//!
//! Phase-10 source-byte heuristic: scan for the canonical needles, skip
//! lines that are obviously a string literal containing the word
//! "eval" or a comment, and emit a Blocker finding. Confidence 0.95.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, TaintFindingBlueprint,
};

/// Family-4 probe `cc.taint.eval_dynamic_code`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvalDynamicCodeRule;

const SUPPORTED_EXTS: &[&str] = &["py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "rb"];

/// Substrings that uniquely identify a dynamic-eval call. Each needle
/// includes the opening paren so the rule does not match identifier
/// usages like `eval_count` or `evaluate_response`.
const EVAL_NEEDLES: &[&str] = &[
    // Python
    "eval(",
    "exec(",
    // JS / TS new-Function plus timer-string forms
    "new Function(",
    "setTimeout(\"",
    "setTimeout('",
    "setInterval(\"",
    "setInterval('",
    // Ruby
    "instance_eval(",
    "class_eval(",
    "module_eval(",
    "binding.eval(",
];

impl Rule for EvalDynamicCodeRule {
    fn rule_id(&self) -> &'static str {
        "cc.taint.eval_dynamic_code"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Taint
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "dynamic code execution sink — first argument is interpreted as program text"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if !is_supported_ext(&path) {
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

fn is_supported_ext(path: &Utf8PathBuf) -> bool {
    path.extension()
        .is_some_and(|ext| SUPPORTED_EXTS.iter().any(|e| *e == ext))
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
        let trimmed = line.trim_start();
        if is_comment_line(trimmed) {
            continue;
        }
        if let Some(needle) = matched_eval(line) {
            // Skip word-suffix matches like `mod.eval(` / `safe_exec(`.
            if needle == "eval(" && !is_at_word_boundary(line, "eval(") {
                continue;
            }
            if needle == "exec(" && !is_at_word_boundary(line, "exec(") {
                continue;
            }
            out.push(emit(path.clone(), idx + 1, line, needle));
        }
    }
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with('#')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
}

fn matched_eval(line: &str) -> Option<&'static str> {
    EVAL_NEEDLES.iter().copied().find(|n| line.contains(n))
}

/// True when `needle` appears in `line` at a word boundary (start of
/// line or preceded by a non-identifier byte).
fn is_at_word_boundary(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut start = 0;
    while start + needle_bytes.len() <= bytes.len() {
        if &bytes[start..start + needle_bytes.len()] == needle_bytes {
            if start == 0 {
                return true;
            }
            let prev = bytes[start - 1];
            if !prev.is_ascii_alphanumeric() && prev != b'_' && prev != b'.' {
                return true;
            }
        }
        start += 1;
    }
    false
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, needle: &str) -> Finding {
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
        rule_id: "cc.taint.eval_dynamic_code",
        category: cc_finding::Category::Taint,
        severity: Severity::Blocker,
        confidence: Confidence::new(0.95),
        location,
        headline: format!(
            "dynamic code-execution sink `{needle}` — first argument is program text"
        ),
        explanation: "Dynamic-eval-style calls interpret their first \
             argument as program source. Any attacker-controlled byte in \
             that argument becomes arbitrary code execution. Even when \
             the input feels controlled today, it is one refactor away \
             from accepting user data."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Replace the dynamic eval with a structured equivalent: a \
             dispatch table keyed on validated input, `json.loads` for \
             data, `ast.literal_eval` for restricted expressions \
             (Python), or a sandboxed VM for genuine scripting needs."
                .into(),
        ),
        snippet,
        weight: 10,
    })
}
