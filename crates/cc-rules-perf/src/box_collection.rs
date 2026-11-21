//! `cc.perf.box_collection` — `Box<Vec<T>>` / `Box<HashMap<K,V>>` /
//! `Box<String>` etc, where the inner type already heap-allocates.
//!
//! Canonical pattern:
//! ```text
//! struct Cache {
//!     entries: Box<Vec<Entry>>,           // double indirection
//!     index:   Box<HashMap<Key, usize>>,  // double indirection
//!     name:    Box<String>,                // double indirection
//! }
//! ```
//! `Vec<T>`, `HashMap<K,V>`, `BTreeMap<K,V>`, and `String` already own
//! a heap buffer. Wrapping them in `Box` adds a second pointer hop on
//! every read and a second allocation on every construction without
//! buying anything (the inner type is already moveable, sized, and
//! heap-resident).
//!
//! OSS source: clippy `box_collection`.
//!
//! Phase-9 source-byte heuristic: scan `.rs` files for field / let
//! declarations of the shape `: Box<{Vec, VecDeque, HashMap,
//! HashSet, BTreeMap, BTreeSet, String}<...>>`. Skip test files and
//! rule-pack source.
//!
//! Confidence 0.95.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Position, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, is_rust_test_path, looks_like_rule_pack_source, PerfFindingBlueprint,
};

/// Family-2 probe R-BOX-COLLECTION.
#[derive(Debug, Default, Clone, Copy)]
pub struct BoxCollectionRule;

const REDUNDANT_INNER: &[&str] = &[
    "Vec<",
    "VecDeque<",
    "HashMap<",
    "HashSet<",
    "BTreeMap<",
    "BTreeSet<",
    "String>",
    "String,",
];

impl Rule for BoxCollectionRule {
    fn rule_id(&self) -> &'static str {
        "cc.perf.box_collection"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Perf
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.95)
    }
    fn description(&self) -> &'static str {
        "`Box<...>` over an already-heap-allocating collection"
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
        if let Some(inner) = detect_box_collection(line) {
            out.push(emit(path.clone(), idx + 1, line, inner));
        }
    }
}

/// Returns the inner-collection name when `line` carries a redundant
/// `Box<Coll<...>>` declaration.
fn detect_box_collection(line: &str) -> Option<&'static str> {
    let mut search_start = 0_usize;
    while let Some(rel) = line[search_start..].find("Box<") {
        let idx = search_start + rel + "Box<".len();
        for inner in REDUNDANT_INNER {
            if line[idx..].starts_with(inner) {
                return Some(extract_label(inner));
            }
        }
        search_start = idx;
    }
    None
}

fn extract_label(token: &str) -> &'static str {
    match token {
        "Vec<" => "Vec",
        "VecDeque<" => "VecDeque",
        "HashMap<" => "HashMap",
        "HashSet<" => "HashSet",
        "BTreeMap<" => "BTreeMap",
        "BTreeSet<" => "BTreeSet",
        "String>" | "String," => "String",
        _ => "collection",
    }
}

fn emit(path: Utf8PathBuf, line_no: usize, line: &str, inner: &'static str) -> Finding {
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
        rule_id: "cc.perf.box_collection",
        severity: Severity::Required,
        confidence: Confidence::new(0.95),
        location,
        headline: format!("`Box<{inner}<...>>` is redundant — `{inner}` already heap-allocates"),
        explanation: format!(
            "`{inner}` already owns a heap buffer. Wrapping it in `Box` \
             adds a second indirection on every access and a second \
             allocator call on every construction without changing the \
             type's move semantics, size, or trait-object behaviour. \
             Drop the `Box` and the type behaves identically with one \
             fewer pointer-chase per read."
        ),
        remediation: Remediation::SuggestedRewrite(format!(
            "Replace `Box<{inner}<...>>` with `{inner}<...>` directly."
        )),
        snippet,
        weight: 3,
    })
}
