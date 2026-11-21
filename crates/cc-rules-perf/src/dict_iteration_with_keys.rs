//! `cc.perf.dict_iteration_with_keys` — Python `for k in d.keys():`
//! pattern.
//!
//! ```python
//! for k in d.keys():            # redundant — `for k in d` is identical
//!     ...
//! if x in d.keys():             # also flagged
//!     ...
//! ```
//! In Python 3 every dict has a default iterator that yields keys.
//! Calling `.keys()` first allocates an extra view object and signals
//! unfamiliarity with the language. ruff `PERF102` / `SIM118` flag the
//! exact same pattern.
//!
//! OSS source: ruff `PERF102` (`incorrect-dict-iterator`) and
//! `SIM118` (`in-dict-keys`).
//!
//! Phase-12 source-byte heuristic: `.py` files only. Match every line
//! whose trimmed content contains either:
//! - `for <bindings> in <expr>.keys():` (PERF102), or
//! - `<expr> in <ident>.keys()` (SIM118).
//!
//! Severity::Nit, confidence 0.95.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path_py, looks_like_rule_pack_source, PerfFindingBlueprint,
};

/// Family-2 perf rule `cc.perf.dict_iteration_with_keys`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DictIterationWithKeysRule;

impl Rule for DictIterationWithKeysRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.dict_iteration_with_keys"
    }
    fn category(&self) -> Category {
        Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "`for k in d.keys()` is identical to `for k in d` — drop `.keys()`"
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
            if is_test_file_path_py(&path) || looks_like_rule_pack_source(&path) {
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
    for (idx, line) in text.lines().enumerate() {
        if let Some(reason) = first_keys_misuse(line) {
            out.push(emit(path.clone(), idx + 1, line, reason));
        }
    }
}

fn first_keys_misuse(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return None;
    }
    if for_in_keys(trimmed) {
        return Some("for-loop");
    }
    if in_keys_membership(trimmed) {
        return Some("membership-test");
    }
    None
}

/// True iff the line shapes as `for <bindings> in <expr>.keys():`.
fn for_in_keys(trimmed: &str) -> bool {
    let Some(rest) = trimmed.strip_prefix("for ") else {
        return false;
    };
    let Some((_, after_in)) = rest.split_once(" in ") else {
        return false;
    };
    contains_keys_call_to_colon(after_in)
}

/// True iff the suffix contains `.keys()` followed (eventually) by `:`
/// — guards against the rare case where the keys call is part of a
/// nested expression that does not terminate the loop.
fn contains_keys_call_to_colon(after_in: &str) -> bool {
    let Some(keys_idx) = after_in.find(".keys()") else {
        return false;
    };
    let after_keys = &after_in[keys_idx + ".keys()".len()..];
    after_keys.contains(':') && !after_keys.starts_with(".")
}

/// True iff the line shapes as `<expr> in <ident>.keys()` (no `for`).
fn in_keys_membership(trimmed: &str) -> bool {
    if trimmed.starts_with("for ") {
        return false;
    }
    let Some(in_idx) = trimmed.find(" in ") else {
        return false;
    };
    let after_in = &trimmed[in_idx + 4..];
    let Some(keys_idx) = after_in.find(".keys()") else {
        return false;
    };
    let after_keys = &after_in[keys_idx + ".keys()".len()..];
    !after_keys.starts_with('.')
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, reason: &'static str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    let headline = match reason {
        "for-loop" => "`for k in d.keys()` is identical to `for k in d` — drop `.keys()`",
        _ => "`x in d.keys()` is identical to `x in d` — drop `.keys()`",
    };
    build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.dict_iteration_with_keys",
        severity: Severity::Nit,
        confidence: Confidence::new(0.95),
        location,
        headline: headline.into(),
        explanation: "Iterating a Python 3 dict directly yields its keys — \
             `for k in d` is exactly the same loop as `for k in \
             d.keys()`. The latter allocates a `dict_keys` view object \
             on every entry to the loop. Membership testing follows the \
             same rule: `x in d` is identical to `x in d.keys()`. The \
             extra `.keys()` doesn't break anything but it does signal \
             unfamiliarity with the dict protocol — reviewers will \
             flag it. ruff PERF102 / SIM118 catch this exact shape."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Drop the `.keys()` call: `for k in d:` / `if k in d:`. \
             If you specifically need a snapshot view to mutate the \
             dict during iteration, write `for k in list(d):` — that \
             intent is now explicit."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
