//! `cc.perf.boxed_local` — function parameter declared `Box<T>` where
//! `T` is a concrete sized type (not a trait object).
//!
//! Canonical pattern:
//! ```text
//! fn process(record: Box<Record>) { ... }    // forces caller heap-alloc
//! fn render(item: Box<Widget>) -> Pixel { ... }
//! ```
//! Forcing callers to box their value is wasteful: every call site
//! must heap-allocate, even when the caller already owns the value on
//! the stack. The right ownership signature is `T` (consume) or `&T`
//! (borrow). `Box<T>` only makes sense for trait objects (`Box<dyn
//! Trait>`) where the size is unknown at compile time.
//!
//! OSS source: clippy `boxed_local`.
//!
//! Phase-9 source-byte heuristic: scan `.rs` files for `fn <name>(...
//! <param>: Box<<concrete>>...)` shapes where `<concrete>` does NOT
//! start with `dyn ` and is not one of the redundant collection types
//! covered by `cc.perf.box_collection`. Skip test files and rule-pack
//! source.
//!
//! Confidence 0.9.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, identifier_ending_at, is_rust_test_path, looks_like_rule_pack_source,
    PerfFindingBlueprint,
};

/// Family-2 probe R-BOXED-LOCAL.
#[derive(Debug, Default, Clone, Copy)]
pub struct BoxedLocalRule;

/// Inner-type prefixes already covered by `cc.perf.box_collection`.
/// Avoid double-firing.
const ALREADY_COVERED: &[&str] = &[
    "Vec<",
    "VecDeque<",
    "HashMap<",
    "HashSet<",
    "BTreeMap<",
    "BTreeSet<",
    "String>",
    "String,",
    "String ",
    "String)",
];

impl Rule for BoxedLocalRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.boxed_local"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        "fn parameter declared `Box<T>` for concrete T forces caller heap-alloc"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file_node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = string_prop(ctx.batch, file_node.id, "path").map(Utf8PathBuf::from)
            else {
                continue;
            };
            if path.extension() != Some("rs") {
                continue;
            }
            if is_rust_test_path(&path) || looks_like_rule_pack_source(&path) {
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
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if !is_fn_signature_line(trimmed) {
            continue;
        }
        if let Some(param) = detect_boxed_local_param(line) {
            out.push(emit(path.clone(), idx + 1, line, &param));
        }
    }
}

fn is_fn_signature_line(trimmed: &str) -> bool {
    trimmed.starts_with("fn ")
        || trimmed.starts_with("pub fn ")
        || trimmed.starts_with("pub(crate) fn ")
        || trimmed.starts_with("pub(super) fn ")
        || trimmed.starts_with("async fn ")
        || trimmed.starts_with("pub async fn ")
        || trimmed.starts_with("const fn ")
        || trimmed.starts_with("pub const fn ")
}

/// Returns the parameter name when the signature has a non-trait
/// `Box<...>` parameter.
fn detect_boxed_local_param(line: &str) -> Option<String> {
    let needle = ": Box<";
    let idx = line.find(needle)?;
    let inner = &line[idx + needle.len()..];
    if inner.starts_with("dyn ") {
        return None;
    }
    if ALREADY_COVERED
        .iter()
        .any(|prefix| inner.starts_with(prefix))
    {
        return None;
    }
    let pre = &line[..idx];
    let name = identifier_ending_at(pre, pre.len())?;
    if name.is_empty() || name == "self" {
        // `self: Box<Self>` is a legitimate boxed-receiver pattern.
        return None;
    }
    Some(name.to_owned())
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, name: &str) -> Finding {
    let pos = Position::new(u32::try_from(line_no).unwrap_or(u32::MAX), 1, 0);
    let location = cc_finding::Location {
        file: path,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    };
    let snippet: String = line.trim().chars().take(180).collect();
    build_finding(PerfFindingBlueprint {
        rule_id: "cc.perf.boxed_local",
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!("parameter `{name}: Box<T>` forces every caller to heap-allocate"),
        explanation: "Concrete-typed `Box<T>` parameters require callers to \
             box their value before invocation, even when they already \
             own it on the stack. The function gets nothing for the \
             extra allocation: it could equally take `T` by value (to \
             consume) or `&T` (to borrow) and operate identically. \
             `Box<T>` is only the right shape for trait objects \
             (`Box<dyn Trait>`) where `T`'s size is unknown."
            .into(),
        remediation: Remediation::SuggestedRewrite(format!(
            "Drop the `Box`: take `{name}: T` if you consume the \
                 value or `{name}: &T` if you only read it. Reserve \
                 `Box<dyn Trait>` parameters for true type erasure."
        )),
        snippet,
        weight: 2,
    })
}
