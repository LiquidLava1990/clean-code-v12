//! `cc.a11y.color_only_signal` — error/state shown by colour alone.
//!
//! Heuristic: walk every [`NodeKind::File`] in the batch; for each
//! non-test, non-rule-pack file, scan source bytes for the canonical
//! "red text" patterns enumerated in
//! `crate::helpers::COLOR_PATTERNS`. For each hit, take a five-line
//! window centred on the hit and look for any iconography / aria
//! marker from `crate::helpers::ICON_HINT_KEYWORDS`. If no marker is
//! present, the colour is the sole signal — emit a finding.
//!
//! Phase-5 simplification: the window is line-oriented. A more precise
//! Phase-6 implementation will scope the search to the enclosing JSX
//! element once the JSX lift exposes attribute structure.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_test_file_path, location_at_offset, looks_like_rule_pack_source,
    I18nA11yFindingBlueprint, COLOR_PATTERNS, ICON_HINT_KEYWORDS,
};

/// Family-15 probe R-A11Y-COLOR-ONLY-SIGNAL.
#[derive(Debug, Default, Clone, Copy)]
pub struct ColorOnlySignalRule;

/// Number of lines on either side of a colour-pattern hit that the
/// probe inspects for iconography hints.
const WINDOW_LINES: usize = 5;

impl Rule for ColorOnlySignalRule {
    fn rule_id(&self) -> &'static str {
        "cc.a11y.color_only_signal"
    }
    fn category(&self) -> Category {
        Category::A11y
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.55)
    }
    fn description(&self) -> &'static str {
        "state communicated by colour alone — no icon / aria-label nearby"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            scan_file(ctx, file_node.id, &mut out);
        }
        out
    }
}

fn scan_file(ctx: &RuleContext<'_>, file_id: NodeId, out: &mut Vec<Finding>) {
    let Some(path) = string_prop(ctx.batch, file_id, "path").map(Utf8PathBuf::from) else {
        return;
    };
    if is_test_file_path(&path) || looks_like_rule_pack_source(&path) {
        return;
    }
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let lower: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    for (offset, needle) in find_color_hits(&lower) {
        if has_icon_hint_in_window(&lower, offset) {
            continue;
        }
        out.push(emit(bytes, offset, needle, &path));
    }
}

/// Every `(offset, needle)` for a colour pattern in `lower`.
fn find_color_hits(lower: &[u8]) -> Vec<(usize, &'static str)> {
    let mut hits: Vec<(usize, &'static str)> = Vec::new();
    for pat in COLOR_PATTERNS {
        let bytes = pat.as_bytes();
        let mut start = 0_usize;
        while let Some(rel) = position_of(&lower[start..], bytes) {
            hits.push((start + rel, *pat));
            start = start + rel + bytes.len();
        }
    }
    hits.sort_by_key(|(off, _)| *off);
    hits
}

fn position_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// True iff any [`ICON_HINT_KEYWORDS`] needle appears within the
/// five-line window centred on `offset`.
fn has_icon_hint_in_window(lower: &[u8], offset: usize) -> bool {
    let (lo, hi) = window_bounds(lower, offset);
    let slice = &lower[lo..hi];
    ICON_HINT_KEYWORDS
        .iter()
        .any(|h| position_of(slice, h.as_bytes()).is_some())
}

/// Compute the byte bounds of a `WINDOW_LINES`-on-each-side window
/// around `offset`.
fn window_bounds(lower: &[u8], offset: usize) -> (usize, usize) {
    let lo = scan_back_lines(lower, offset, WINDOW_LINES);
    let hi = scan_forward_lines(lower, offset, WINDOW_LINES);
    (lo, hi.min(lower.len()))
}

fn scan_back_lines(bytes: &[u8], from: usize, count: usize) -> usize {
    // Walk backwards from `from`, decrementing first then checking the
    // byte at the new position — `bytes[idx]` after `idx -= 1` is the
    // byte just stepped over.
    let walk = |idx: usize| -> Option<(usize, bool)> {
        let next = idx.checked_sub(1)?;
        Some((next, bytes[next] == b'\n'))
    };
    scan_lines_with(from.min(bytes.len()), count, walk)
}

fn scan_forward_lines(bytes: &[u8], from: usize, count: usize) -> usize {
    // Walk forwards: check the byte at the current position THEN
    // advance. `bytes[idx]` is consumed before stepping.
    let walk = |idx: usize| -> Option<(usize, bool)> {
        let crossed = *bytes.get(idx)? == b'\n';
        Some((idx + 1, crossed))
    };
    scan_lines_with(from.min(bytes.len()), count, walk)
}

/// Generic step-loop over a byte stream that stops once `count`
/// newlines have been crossed or the iteration source is exhausted.
/// `step` returns `(next_idx, crossed_newline)` or `None` when the
/// caller has hit a bound.
fn scan_lines_with<F>(start: usize, count: usize, mut step: F) -> usize
where
    F: FnMut(usize) -> Option<(usize, bool)>,
{
    let mut idx = start;
    let mut newlines = 0_usize;
    while newlines < count {
        let Some((next, crossed)) = step(idx) else {
            return idx;
        };
        idx = next;
        if crossed {
            newlines += 1;
        }
    }
    idx
}

fn emit(bytes: &[u8], offset: usize, needle: &'static str, path: &Utf8PathBuf) -> Finding {
    let location = location_at_offset(path.clone(), bytes, offset, needle.len());
    build_finding(I18nA11yFindingBlueprint {
        rule_id: "cc.a11y.color_only_signal",
        category: Category::A11y,
        severity: Severity::Nit,
        confidence: Confidence::new(0.55),
        location,
        headline: format!("`{needle}` signals state via colour alone"),
        explanation: "The pattern signals an error / warning / success state through \
             colour with no accompanying icon, label, or aria attribute. \
             Users with colour-vision deficiencies or monochrome displays \
             cannot perceive the state. WCAG 2.1 SC 1.4.1 requires colour \
             never to be the sole means of conveying information."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Pair the colour with a non-visual cue: an inline `<svg>` icon, \
             a leading `IconError` / `IconWarn` component, an `aria-label`, \
             or a textual prefix (e.g. `Error: …`). Keep the colour as a \
             secondary signal, never the only one."
                .into(),
        ),
        snippet: needle.to_owned(),
        weight: 1,
    })
}
