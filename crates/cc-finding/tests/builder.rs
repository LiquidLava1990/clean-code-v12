//! Builder validation tests.

mod common;

use cc_finding::{Category, CostClaim, FindingBuilder, FindingError, Severity};
use common::{sample_evidence, sample_location, sample_message, sample_probe_version};

#[test]
fn builder_validates_required() {
    let err = FindingBuilder::new()
        .category(Category::Shape)
        .location(sample_location())
        .message(sample_message())
        .evidence(sample_evidence("x"))
        .severity(Severity::Required)
        .cost(CostClaim::BlockingDebt { weight: 1 })
        .probe_version(sample_probe_version())
        .build()
        .unwrap_err();
    match err {
        FindingError::MissingField { field } => assert_eq!(field, "rule_id"),
        other => panic!("expected MissingField, got {other:?}"),
    }
}

#[test]
fn builder_error_message_is_actionable() {
    let err = FindingBuilder::new().rule_id("cc.x.y").build().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("category"), "msg = {msg}");
    assert!(msg.contains(".category("), "msg = {msg}");
    assert!(msg.contains(".build()"), "msg = {msg}");
}

#[test]
fn builder_populates_suppress_key() {
    let f = FindingBuilder::new()
        .rule_id("cc.shape.fn_length")
        .category(Category::Shape)
        .location(sample_location())
        .message(sample_message())
        .evidence(sample_evidence("fn x() {}"))
        .severity(Severity::Nit)
        .confidence(0.7)
        .cost(CostClaim::BlockingDebt { weight: 1 })
        .probe_version(sample_probe_version())
        .build()
        .expect("builds");
    assert_ne!(f.suppress_key, cc_finding::SuppressKey::ZERO);
}
