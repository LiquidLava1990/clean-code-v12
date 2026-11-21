//! `cc.bug.furb_dict_get_with_none_default` — `d.get(key, None)`. The
//! `None` default is identical to omitting it (`dict.get` already
//! returns `None` for missing keys), so the explicit argument is noise
//! that obscures the actual semantics on every read.
//!
//! Mirrors ruff `FURB186` (no-default-on-dict-get) — refurb-derived.
//!
//! Phase-10 detector: scan every `.py` file once for `<expr>.get(...,
//! None)` calls. The receiver may be any expression — `d`, `self.cache`,
//! `os.environ`, etc.; the marker is the trailing `, None)` after at
//! least one comma.
//!
//! Severity: `Nit`. Confidence 0.95 — the call shape is concrete; false
//! positives are limited to objects that override `get(key, default)`
//! with a custom None semantic, which is exotic.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, looks_like_rule_pack_source, BugFindingBlueprint,
};

/// Family-3 probe `cc.bug.furb_dict_get_with_none_default`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FurbDictGetWithNoneDefaultRule;

impl Rule for FurbDictGetWithNoneDefaultRule {
    fn rule_id(&self) -> &'static str {
        "cc.bug.furb_dict_get_with_none_default"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "`d.get(key, None)` — the `None` default is redundant"
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
        if line_has_get_with_none_default(line) {
            out.push(emit(path.clone(), line_idx + 1, line));
        }
    }
}

/// True iff the line contains `.get(<args>, None)` with `None` as the
/// trailing positional argument. We scan every occurrence of `.get(`
/// because there may be multiple `.get(...)` chains on one line.
fn line_has_get_with_none_default(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut start = 0usize;
    while let Some(found) = line[start..].find(".get(") {
        let abs = start + found;
        let inner_start = abs + ".get(".len();
        let Some(close) = match_paren(bytes, inner_start) else {
            return false;
        };
        if call_ends_with_none(line, inner_start, close) {
            return true;
        }
        start = close + 1;
    }
    false
}

fn match_paren(bytes: &[u8], inner_start: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut idx = inner_start;
    while idx < bytes.len() {
        match bytes[idx] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

/// True iff the substring `[inner_start, close)` ends with `, None`
/// (top-level — ignoring nested brackets) and contains at least one
/// top-level comma (so we know the call has 2+ args).
fn call_ends_with_none(line: &str, inner_start: usize, close: usize) -> bool {
    if close <= inner_start {
        return false;
    }
    let inner = &line[inner_start..close];
    let last_top_comma = top_level_last_comma(inner);
    let Some(comma_idx) = last_top_comma else {
        return false;
    };
    let after_comma = inner[comma_idx + 1..].trim();
    after_comma == "None"
}

fn top_level_last_comma(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut last: Option<usize> = None;
    for (idx, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => last = Some(idx),
            _ => {}
        }
    }
    last
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str) -> Finding {
    let line_no_u32 = u32::try_from(line_no).unwrap_or(u32::MAX);
    let pos = Position::new(line_no_u32, 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(BugFindingBlueprint {
        rule_id: "cc.bug.furb_dict_get_with_none_default",
        severity: Severity::Nit,
        confidence: Confidence::new(0.95),
        location,
        headline: "`.get(key, None)` — the `None` default is redundant".into(),
        explanation: "`dict.get(key)` already returns `None` for missing \
             keys; passing `None` as the explicit default produces the \
             exact same value. The redundant argument adds reading load \
             — every reviewer pauses to ask whether the `None` is \
             load-bearing — and obscures legitimate `get(key, sentinel)` \
             calls in the same file."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Drop the `None` argument: `d.get(key)`. Mirrors ruff FURB186 \
             autofix. If the call is meant to express \"the lookup may \
             miss and `None` is the chosen sentinel,\" prefer a typed \
             `Optional[V]` annotation on the receiver — that documents \
             the intent at the type level instead of by argument noise."
                .into(),
        ),
        snippet,
        weight: 1,
    })
}
