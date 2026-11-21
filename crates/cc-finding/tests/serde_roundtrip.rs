//! Full Finding JSON round-trip test.

mod common;

use cc_finding::Finding;
use common::sample_finding;

#[test]
fn finding_serde_roundtrip() {
    let original = sample_finding("fn original() { 1 + 1 }");
    let json = serde_json::to_string_pretty(&original).expect("serialise");
    let parsed: Finding = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(parsed, original);
}
