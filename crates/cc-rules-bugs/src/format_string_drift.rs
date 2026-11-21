//! `cc.bug.format_string_drift` — printf-style call where the placeholder
//! count in the literal format string disagrees with the argument count
//! supplied at the call site.
//!
//! Detects the canonical formatter idioms across the four supported
//! languages:
//!
//! - Go:     `fmt.Sprintf` / `fmt.Printf` / `fmt.Errorf` — placeholders
//!           start with `%` (`%s`, `%d`, `%v`, …).
//! - Rust:   `format!` / `println!` / `print!` / `write!` / `writeln!` —
//!           placeholders are `{}` / `{:?}` / `{:0?}` style braces.
//! - Python: `"%s ... %d" % (a, b)` — same `%` placeholders. Detected
//!           when the call's `callee_ref` looks like a `%` operator.
//!           (Phase-7: focus on `.format(...)` and `str % tuple` is
//!           deferred — frontends emit those as Calls inconsistently.)
//! - JS/TS:  `console.log` template-literal style is NOT detected here
//!           because frontends do not yet expose template-literal
//!           placeholders as separate args.
//!
//! Phase-7 conservative: only fires when the literal first argument is
//! a [`NodeKind::Literal`] sibling of the call AND the call carries an
//! `arg_count` property. Variadic / `...args` spread is NOT flagged.

use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{ast_children, node_by_id, node_kind, nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, callee_text, enclosing_file_path, is_test_file_path, location_from_node,
    looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe R-FORMAT-DRIFT.
#[derive(Debug, Default, Clone, Copy)]
pub struct FormatStringDriftRule;

const PERCENT_FORMATTERS: &[&str] = &[
    "fmt.Sprintf",
    "fmt.Printf",
    "fmt.Fprintf",
    "fmt.Errorf",
    "log.Printf",
];

const BRACE_FORMATTERS: &[&str] = &[
    "format!",
    "println!",
    "print!",
    "write!",
    "writeln!",
    "eprintln!",
    "eprint!",
];

impl Rule for FormatStringDriftRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.format_string_drift"
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
        "format-string placeholder count disagrees with argument count"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for call in nodes_of_kind(ctx.batch, NodeKind::Call) {
            if let Some(finding) = check_call(ctx, call.id) {
                out.push(finding);
            }
        }
        out
    }
}

fn check_call(ctx: &RuleContext<'_>, call: NodeId) -> Option<Finding> {
    let callee = callee_text(ctx.batch, call);
    let style = classify(&callee)?;
    let path = enclosing_file_path(ctx.batch, call)?;
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return None;
    }
    let format_lit = first_string_literal_child(ctx, call)?;
    let placeholders = match style {
        Style::Percent => count_percent_placeholders(&format_lit),
        Style::Brace => count_brace_placeholders(&format_lit),
    };
    let arg_count = uint_prop(ctx, call, "arg_count")?;
    // arg_count includes the format string itself; subtract 1.
    let value_args = arg_count.saturating_sub(1);
    if placeholders == value_args {
        return None;
    }
    let location = location_from_node(ctx.batch, call, path);
    Some(emit(
        location,
        &callee,
        &format_lit,
        placeholders,
        value_args,
    ))
}

#[derive(Debug, Clone, Copy)]
enum Style {
    Percent,
    Brace,
}

fn classify(callee: &str) -> Option<Style> {
    if PERCENT_FORMATTERS.iter().any(|n| callee.contains(n)) {
        return Some(Style::Percent);
    }
    if BRACE_FORMATTERS
        .iter()
        .any(|n| callee == *n || callee.ends_with(n))
    {
        return Some(Style::Brace);
    }
    None
}

fn first_string_literal_child(ctx: &RuleContext<'_>, call: NodeId) -> Option<String> {
    for child in ast_children(ctx.batch, call) {
        if node_kind(ctx.batch, child) == Some(NodeKind::Literal) {
            if let Some(value) = string_prop(ctx.batch, child, "value") {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn count_percent_placeholders(s: &str) -> u64 {
    count_placeholders(s, &PERCENT_SCANNER)
}

fn count_brace_placeholders(s: &str) -> u64 {
    count_placeholders(s, &BRACE_SCANNER)
}

/// Predicate-driven scanner that walks `s` once and returns the number
/// of placeholders the configured [`PlaceholderScanner`] accepts.
///
/// Both formatter dialects (`%`-style and `{}`-style) share this loop
/// shape — the per-dialect differences live in the predicate table.
fn count_placeholders(s: &str, scanner: &PlaceholderScanner) -> u64 {
    let bytes = s.as_bytes();
    let mut count: u64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let Some(step) = (scanner.step)(s, bytes, i) else {
            i += 1;
            continue;
        };
        if step.counted {
            count = count.saturating_add(1);
        }
        i = step.next_index;
    }
    count
}

/// Outcome of a single [`PlaceholderScanner::step`] — how far to advance
/// the cursor and whether this advance counted as a placeholder.
struct ScanStep {
    next_index: usize,
    counted: bool,
}

/// Predicate table that drives [`count_placeholders`]. One scanner per
/// formatter dialect; both share the outer walk so no per-dialect
/// nesting is needed.
struct PlaceholderScanner {
    step: fn(&str, &[u8], usize) -> Option<ScanStep>,
}

const PERCENT_SCANNER: PlaceholderScanner = PlaceholderScanner { step: percent_step };

const BRACE_SCANNER: PlaceholderScanner = PlaceholderScanner { step: brace_step };

/// Advance past one `%`-style placeholder starting at `i`.
fn percent_step(_s: &str, bytes: &[u8], i: usize) -> Option<ScanStep> {
    if bytes[i] != b'%' || i + 1 >= bytes.len() {
        return None;
    }
    if bytes[i + 1] == b'%' {
        return Some(ScanStep {
            next_index: i + 2,
            counted: false,
        });
    }
    let mut j = i + 1;
    while j < bytes.len() && b"+-# 0123456789.*".contains(&bytes[j]) {
        j += 1;
    }
    if j >= bytes.len() {
        return Some(ScanStep {
            next_index: j,
            counted: false,
        });
    }
    Some(ScanStep {
        next_index: j + 1,
        counted: true,
    })
}

/// Advance past one `{}`-style placeholder starting at `i`.
fn brace_step(s: &str, bytes: &[u8], i: usize) -> Option<ScanStep> {
    if bytes[i] != b'{' {
        return None;
    }
    if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
        return Some(ScanStep {
            next_index: i + 2,
            counted: false,
        });
    }
    let close = find_byte(bytes, b'}', i + 1)?;
    let inner = &s[i + 1..close];
    let counted = !is_named_or_indexed(inner);
    Some(ScanStep {
        next_index: close + 1,
        counted,
    })
}

/// Linear search for `needle` in `bytes` starting at `from`.
fn find_byte(bytes: &[u8], needle: u8, from: usize) -> Option<usize> {
    bytes[from..]
        .iter()
        .position(|b| *b == needle)
        .map(|off| from + off)
}

fn is_named_or_indexed(inner: &str) -> bool {
    // {name} / {0} / {0:?} are positional / named — they do consume an
    // arg, but Phase-7 only counts *implicit* `{}` placeholders against
    // arg_count to avoid false positives on Rust's named-arg formatter.
    let head = inner.split(':').next().unwrap_or("");
    !head.is_empty()
}

fn uint_prop(ctx: &RuleContext<'_>, id: NodeId, key: &str) -> Option<u64> {
    let node = node_by_id(ctx.batch, id)?;
    match node.prop(key)? {
        cc_cpg::Value::Uint(v) => Some(*v),
        cc_cpg::Value::Int(v) if *v >= 0 => Some(*v as u64),
        _ => None,
    }
}

fn emit(
    location: cc_finding::Location,
    callee: &str,
    format_lit: &str,
    placeholders: u64,
    value_args: u64,
) -> Finding {
    let snippet: String = format_lit.chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.format_string_drift",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(
            "`{callee}` format string has {placeholders} placeholder(s) but {value_args} argument(s)"
        ),
        explanation: format!(
            "The format string `\"{snippet}\"` contains {placeholders} \
             placeholder(s), but `{callee}` was passed {value_args} value \
             argument(s). At runtime this either truncates output (too few \
             args), prints `%!s(MISSING)` / `<missing>` markers, or panics."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Re-count the placeholders against the value arguments and add / \
             remove arguments to match. If the count drift is from a recent \
             refactor, prefer named placeholders (`{name}` / `%[1]s`) so the \
             compiler / linter catches further drift."
                .into(),
        ),
        snippet,
        weight: 4,
    })
}
