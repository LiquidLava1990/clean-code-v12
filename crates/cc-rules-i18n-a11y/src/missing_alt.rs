//! `cc.a11y.missing_alt` — image without alt text.
//!
//! Heuristic: enumerate every [`NodeKind::File`] whose `language` is
//! JSX-flavour (`jsx` / `tsx` / `javascriptreact` / `typescriptreact`).
//! Read the file's source bytes and case-insensitively scan for `<img `
//! or `<image ` open tags. For each hit, locate the closing `>` of the
//! same tag and inspect the substring; if it does NOT contain `alt=`,
//! emit a finding. Skips test files.
//!
//! The probe deliberately works on source bytes — Phase-5 frontends do
//! not yet lift JSX attribute structure into typed CPG nodes, so a
//! source-level scan keeps the probe useful without blocking on the
//! Phase-6 JSX lift.

use camino::Utf8PathBuf;
use cc_cpg::{NodeId, NodeKind};
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_jsx_like_language, is_test_file_path, location_at_offset,
    I18nA11yFindingBlueprint,
};

/// Family-15 probe R-A11Y-MISSING-ALT.
#[derive(Debug, Default, Clone, Copy)]
pub struct MissingAltRule;

const TAG_NEEDLES: &[&str] = &[
    "<img ", "<img\t", "<img\n", "<image ", "<image\t", "<image\n",
];

impl Rule for MissingAltRule {
    fn rule_id(&self) -> &'static str {
        "cc.a11y.missing_alt"
    }
    fn category(&self) -> Category {
        Category::A11y
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "JSX <img>/<image> tag missing an `alt` attribute"
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
    if !is_jsx_like_language(ctx.batch, file_id) {
        return;
    }
    let Some(path) = file_path_of(ctx, file_id) else {
        return;
    };
    if is_test_file_path(&path) {
        return;
    }
    let bytes = ctx.source.get(path.as_path());
    if bytes.is_empty() {
        return;
    }
    let lower = lowercase_bytes(bytes);
    for offset in find_tag_offsets(&lower) {
        if let Some(finding) = check_tag_at(bytes, &lower, offset, &path) {
            out.push(finding);
        }
    }
}

fn file_path_of(ctx: &RuleContext<'_>, file_id: NodeId) -> Option<Utf8PathBuf> {
    cc_frontend::query::string_prop(ctx.batch, file_id, "path").map(Utf8PathBuf::from)
}

fn lowercase_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(u8::to_ascii_lowercase).collect()
}

/// Return every byte offset that opens a `<img` or `<image` tag.
fn find_tag_offsets(lower: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    for needle in TAG_NEEDLES {
        let mut start = 0_usize;
        let bytes = needle.as_bytes();
        while let Some(rel) = window_position(&lower[start..], bytes) {
            hits.push(start + rel);
            start = start + rel + bytes.len();
        }
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

/// Naive substring search; fine for Phase-5 scan budget.
fn window_position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn check_tag_at(bytes: &[u8], lower: &[u8], offset: usize, path: &Utf8PathBuf) -> Option<Finding> {
    let close = find_tag_close(lower, offset)?;
    let tag_lower = &lower[offset..close];
    if window_position(tag_lower, b"alt=").is_some() {
        return None;
    }
    let span = close.saturating_sub(offset).saturating_add(1);
    let location = location_at_offset(path.clone(), bytes, offset, span);
    let preview = std::str::from_utf8(&bytes[offset..close.min(bytes.len())])
        .unwrap_or("<img …>")
        .to_owned();
    Some(build_finding(I18nA11yFindingBlueprint {
        rule_id: "cc.a11y.missing_alt",
        category: Category::A11y,
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: "image element is missing an `alt` attribute".into(),
        explanation: "Every `<img>` / `<image>` element needs an `alt` \
             attribute. Screen readers fall back to the `src` URL when the \
             attribute is absent — a hostile experience that often leaks \
             internal CDN paths to assistive-tech users. Decorative images \
             use `alt=\"\"`; meaningful images use a short description."
            .into(),
        remediation: Remediation::SuggestedRewrite(
            "Add `alt=\"…\"` to the tag. Use `alt=\"\"` for purely \
             decorative images, otherwise a short description of the \
             image's purpose."
                .into(),
        ),
        snippet: preview,
        weight: 2,
    }))
}

/// Find the byte offset of the matching `>` for the tag opening at
/// `offset`. Stops at the first `>` whose prior byte is not `=` (which
/// would indicate a `>=` token from an embedded JS expression — rare in
/// JSX attributes but cheaper to avoid than to recover from).
fn find_tag_close(lower: &[u8], offset: usize) -> Option<usize> {
    let limit = (offset + 4096).min(lower.len());
    for idx in offset..limit {
        if lower[idx] == b'>' && (idx == 0 || lower[idx - 1] != b'=') {
            return Some(idx);
        }
    }
    None
}
