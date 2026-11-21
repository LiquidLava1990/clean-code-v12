//! Unit tests for [`crate::to_rdjson::to_rdjson`].

use cc_finding::Severity;

use crate::doc::{RdSeverity, SourceMeta};
use crate::test_support::{
    finding_with_fix, llm_rewrite_fix, safe_diff_fix, sample_finding, unsafe_diff_fix,
};
use crate::to_rdjson::{severity_to_rd, to_rdjson};

const META: SourceMeta = SourceMeta::new(
    "clean-code-v12",
    "https://example.org/cc",
    "https://docs.example.org/rules",
);

#[test]
fn severity_mapping_blocker_to_error() {
    assert_eq!(severity_to_rd(Severity::Blocker), RdSeverity::Error);
    let v = serde_json::to_value(severity_to_rd(Severity::Blocker)).unwrap();
    assert_eq!(v, serde_json::json!("ERROR"));
}

#[test]
fn severity_mapping_required_to_warning() {
    assert_eq!(severity_to_rd(Severity::Required), RdSeverity::Warning);
    let v = serde_json::to_value(severity_to_rd(Severity::Required)).unwrap();
    assert_eq!(v, serde_json::json!("WARNING"));
}

#[test]
fn severity_mapping_nit_to_info() {
    assert_eq!(severity_to_rd(Severity::Nit), RdSeverity::Info);
    let v = serde_json::to_value(severity_to_rd(Severity::Nit)).unwrap();
    assert_eq!(v, serde_json::json!("INFO"));
}

#[test]
fn code_url_derived_from_rule_id() {
    let f = sample_finding("cc.shape.fn_length", Severity::Required);
    let diag = to_rdjson(&f, META);
    let code = diag.code.expect("code field is always populated");
    assert_eq!(code.value, "cc.shape.fn_length");
    let url = code.url.expect("doc URL is populated");
    assert!(
        url.contains("/shape/cc.shape.fn_length.md"),
        "expected family-derived URL, got `{url}`",
    );
}

#[test]
fn code_url_falls_back_for_non_cc_rule() {
    let f = sample_finding("custom_rule", Severity::Nit);
    let diag = to_rdjson(&f, META);
    let url = diag.code.unwrap().url.unwrap();
    assert!(url.ends_with("/custom_rule.md"), "got `{url}`");
}

#[test]
fn safe_diff_emits_one_suggestion_per_edit() {
    let f = finding_with_fix(Severity::Required, safe_diff_fix());
    let diag = to_rdjson(&f, META);
    assert_eq!(diag.suggestions.len(), 2);
    assert_eq!(diag.suggestions[0].text, "renamed_fn");
}

#[test]
fn unsafe_diff_skips_suggestions() {
    let f = finding_with_fix(Severity::Required, unsafe_diff_fix());
    let diag = to_rdjson(&f, META);
    assert!(diag.suggestions.is_empty());
}

#[test]
fn llm_rewrite_skipped() {
    let f = finding_with_fix(Severity::Required, llm_rewrite_fix());
    let diag = to_rdjson(&f, META);
    assert!(diag.suggestions.is_empty());
}

#[test]
fn message_includes_headline_and_remediation() {
    let f = sample_finding("cc.shape.fn_length", Severity::Required);
    let diag = to_rdjson(&f, META);
    assert!(
        diag.message.contains("function exceeds 50 lines"),
        "headline missing from message: `{}`",
        diag.message
    );
    assert!(
        diag.message.contains("see docs:"),
        "remediation summary missing from message: `{}`",
        diag.message
    );
}

#[test]
fn location_path_is_forward_slashed() {
    let f = sample_finding("cc.shape.fn_length", Severity::Required);
    let diag = to_rdjson(&f, META);
    assert!(!diag.location.path.contains('\\'));
}

#[test]
fn golden_snapshot() {
    let f = sample_finding("cc.shape.fn_length", Severity::Blocker);
    let diag = to_rdjson(&f, META);
    let json = serde_json::to_string_pretty(&diag).unwrap();
    insta::assert_snapshot!("rdjson_diagnostic", json);
}
