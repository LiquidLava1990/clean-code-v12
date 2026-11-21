//! Suppress-key stability properties.

mod common;

use cc_finding::SuppressKey;
use common::{sample_finding, sample_finding_with_node};

#[test]
fn suppress_key_stable_across_whitespace() {
    let a = sample_finding_with_node("fn   x ( ) {  return  1 ; }", "node:1");
    let b = sample_finding_with_node("fn x() {\n    return 1;\n}", "node:1");
    assert_eq!(
        SuppressKey::from_finding(&a),
        SuppressKey::from_finding(&b),
        "whitespace edits must not change suppress key"
    );
}

#[test]
fn suppress_key_stable_across_import_reorder() {
    let snippet_a = "use std::io;\nuse std::fs;\nfn x() { 1 }";
    let snippet_b = "use std::fs;\nuse std::io;\nfn x() { 1 }";
    let a = sample_finding_with_node(snippet_a, "node:1");
    let b = sample_finding_with_node(snippet_b, "node:1");
    assert_eq!(
        SuppressKey::from_finding(&a),
        SuppressKey::from_finding(&b),
        "import re-ordering must not change suppress key"
    );
}

#[test]
fn suppress_key_stable_across_comment_edits() {
    let snippet_a = "fn x() { /* old comment */ 1 }";
    let snippet_b = "fn x() { /* COMPLETELY different */ 1 }";
    let a = sample_finding_with_node(snippet_a, "node:1");
    let b = sample_finding_with_node(snippet_b, "node:1");
    assert_eq!(
        SuppressKey::from_finding(&a),
        SuppressKey::from_finding(&b),
        "comment edits must not change suppress key"
    );
}

#[test]
fn suppress_key_changes_on_real_change() {
    let a = sample_finding_with_node("fn x() { 1 }", "node:1");
    let b = sample_finding_with_node("fn x() { 2 }", "node:2");
    assert_ne!(
        SuppressKey::from_finding(&a),
        SuppressKey::from_finding(&b),
        "different code must produce different suppress keys"
    );
}

#[test]
fn suppress_key_hex_is_64_chars() {
    let f = sample_finding("fn x() {}");
    assert_eq!(f.suppress_key.to_hex().len(), 64);
}

#[test]
fn suppress_key_serde_roundtrip() {
    let f = sample_finding("fn x() {}");
    let json = serde_json::to_string(&f.suppress_key).unwrap();
    let back: SuppressKey = serde_json::from_str(&json).unwrap();
    assert_eq!(f.suppress_key, back);
}
