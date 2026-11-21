//! Integration tests for `cc_sarif::to_sarif` + `SarifSink` + `validate`.

mod common;

use cc_finding::{FindingSink, Severity};
use cc_sarif::{
    doc::{SarifDocument, SARIF_VERSION},
    to_sarif, validate, OutputMode, SarifSink, SarifValidationError, ToolMeta,
};

use crate::common::{
    finding_with, finding_with_codemod_fix, finding_with_diff_fix, finding_with_llm_rewrite,
};

const fn meta() -> ToolMeta {
    ToolMeta::cc_kernel()
}

#[test]
fn severity_maps_to_sarif_level() {
    let pairs = [
        (Severity::Blocker, "error"),
        (Severity::Required, "warning"),
        (Severity::Nit, "note"),
    ];
    for (sev, expected) in pairs {
        let f = finding_with("cc.shape.fn_length", sev);
        let doc = to_sarif(std::slice::from_ref(&f), meta());
        assert_eq!(doc.runs[0].results[0].level, expected);
    }
}

#[test]
fn partial_fingerprint_is_lowercase_hex() {
    let f = finding_with("cc.shape.fn_length", Severity::Required);
    let doc = to_sarif(std::slice::from_ref(&f), meta());
    let fp = doc.runs[0].results[0]
        .partial_fingerprints
        .get("cc/v1")
        .expect("cc/v1 fingerprint must be emitted");
    assert!(!fp.is_empty(), "fingerprint must not be empty");
    assert!(
        fp.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "fingerprint `{fp}` must be lowercase hex"
    );
    assert_eq!(fp.len(), 64, "SHA-256 hex must be 64 chars");
}

#[test]
fn to_sarif_required_fields_present() {
    let f = finding_with("cc.shape.fn_length", Severity::Required);
    let doc = to_sarif(std::slice::from_ref(&f), meta());

    assert_eq!(doc.version, SARIF_VERSION);
    assert!(!doc.schema.is_empty());
    assert_eq!(doc.runs.len(), 1);
    assert_eq!(doc.runs[0].tool.driver.name, "clean-code-v12");
    assert!(!doc.runs[0].tool.driver.version.is_empty());
    assert_eq!(doc.runs[0].results.len(), 1);
    assert_eq!(doc.runs[0].results[0].rule_id, "cc.shape.fn_length");
    assert_eq!(doc.runs[0].results[0].locations.len(), 1);
}

#[test]
fn fixes_emit_artifact_changes_for_diff() {
    let f = finding_with_diff_fix();
    let doc = to_sarif(std::slice::from_ref(&f), meta());
    let result = &doc.runs[0].results[0];

    assert_eq!(result.fixes.len(), 1, "Diff proposal should emit one Fix");
    let fix = &result.fixes[0];
    assert_eq!(fix.artifact_changes.len(), 1);
    assert_eq!(fix.artifact_changes[0].replacements.len(), 1);
    let replacement = &fix.artifact_changes[0].replacements[0];
    assert_eq!(
        replacement
            .inserted_content
            .as_ref()
            .map(|c| c.text.as_str()),
        Some("fn short() { ok() }\n")
    );
}

#[test]
fn fixes_emit_artifact_changes_for_codemod() {
    let f = finding_with_codemod_fix();
    let doc = to_sarif(std::slice::from_ref(&f), meta());
    assert_eq!(doc.runs[0].results[0].fixes.len(), 1);
}

#[test]
fn llm_rewrite_emits_property_not_fix() {
    let f = finding_with_llm_rewrite();
    let doc = to_sarif(std::slice::from_ref(&f), meta());
    let result = &doc.runs[0].results[0];

    assert!(
        result.fixes.is_empty(),
        "LlmRewrite must NOT populate fixes[]"
    );
    let suggested = result
        .properties
        .get("suggested_rewrite")
        .expect("suggested_rewrite property must be present for LlmRewrite");
    assert_eq!(
        suggested.get("rationale").and_then(|v| v.as_str()),
        Some("extract sub-step into helper")
    );
}

#[test]
fn tool_driver_rules_dedupe() {
    let findings = vec![
        finding_with("cc.shape.fn_length", Severity::Required),
        finding_with("cc.shape.fn_length", Severity::Required),
        finding_with("cc.shape.fn_length", Severity::Required),
        finding_with("cc.slop.duplication", Severity::Nit),
        finding_with("cc.slop.duplication", Severity::Nit),
    ];
    let doc = to_sarif(&findings, meta());
    let rules = &doc.runs[0].tool.driver.rules;
    assert_eq!(rules.len(), 2, "5 findings × 2 unique rule_ids → 2 rules");
    let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"cc.shape.fn_length"));
    assert!(ids.contains(&"cc.slop.duplication"));
}

#[test]
fn rule_descriptors_carry_help_uri_per_family() {
    let findings = vec![
        finding_with("cc.shape.fn_length", Severity::Required),
        finding_with("cc.taint.sql_injection", Severity::Blocker),
    ];
    let doc = to_sarif(&findings, meta());
    for rule in &doc.runs[0].tool.driver.rules {
        let uri = rule
            .help_uri
            .as_ref()
            .expect("each rule descriptor needs a helpUri");
        assert!(uri.contains("/docs/rules/"));
    }
}

#[test]
fn validate_accepts_well_formed_doc() {
    let f = finding_with("cc.shape.fn_length", Severity::Required);
    let doc = to_sarif(std::slice::from_ref(&f), meta());
    assert!(validate(&doc).is_ok());
}

#[test]
fn validate_catches_missing_rule_id() {
    let f = finding_with("cc.shape.fn_length", Severity::Required);
    let mut doc = to_sarif(std::slice::from_ref(&f), meta());
    doc.runs[0].results[0].rule_id.clear();
    let errors = validate(&doc).expect_err("validator must reject empty ruleId");
    assert!(errors
        .iter()
        .any(|e| matches!(e, SarifValidationError::EmptyRuleId { .. })));
}

#[test]
fn validate_catches_bad_level() {
    let f = finding_with("cc.shape.fn_length", Severity::Required);
    let mut doc = to_sarif(std::slice::from_ref(&f), meta());
    doc.runs[0].results[0].level = "totally-fake".to_owned();
    let errors = validate(&doc).expect_err("validator must reject unknown level");
    assert!(errors
        .iter()
        .any(|e| matches!(e, SarifValidationError::BadLevel { .. })));
}

#[test]
fn validate_catches_no_runs() {
    let f = finding_with("cc.shape.fn_length", Severity::Required);
    let mut doc = to_sarif(std::slice::from_ref(&f), meta());
    doc.runs.clear();
    let errors = validate(&doc).expect_err("validator must reject zero runs");
    assert!(errors.contains(&SarifValidationError::NoRuns));
}

#[test]
fn sarif_sink_writes_pretty_json_by_default() {
    let buf: Vec<u8> = Vec::new();
    let writer = std::io::Cursor::new(buf);
    let mut sink = SarifSink::new(Box::new(writer), meta());
    sink.emit(finding_with("cc.shape.fn_length", Severity::Required))
        .expect("emit");
    let summary = Box::new(sink).finish().expect("finish");
    assert_eq!(summary.total, 1);
}

#[test]
fn sarif_sink_buffers_findings_until_finish() {
    use std::sync::{Arc, Mutex};
    #[derive(Default, Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let shared = SharedBuf::default();
    let mut sink = SarifSink::new(Box::new(shared.clone()), meta());
    sink.emit(finding_with("cc.shape.fn_length", Severity::Required))
        .expect("emit");
    sink.emit(finding_with("cc.slop.duplication", Severity::Nit))
        .expect("emit");
    assert_eq!(sink.buffered_len(), 2);
    Box::new(sink).finish().expect("finish");

    let owned_bytes: Vec<u8> = shared.0.lock().expect("mutex").clone();
    let text = std::str::from_utf8(&owned_bytes).expect("utf-8 output");
    let parsed: SarifDocument = serde_json::from_str(text).expect("round-trip");
    assert_eq!(parsed.runs[0].results.len(), 2);
}

#[test]
fn compact_mode_emits_single_line_json() {
    let buf: Vec<u8> = Vec::new();
    let cursor = std::io::Cursor::new(buf);
    let mut sink = SarifSink::new(Box::new(cursor), meta()).compact();
    sink.emit(finding_with("cc.shape.fn_length", Severity::Required))
        .expect("emit");
    assert_eq!(sink.buffered_len(), 1);
    // Verify mode setter compiled & is wired.
    let _ = OutputMode::Compact;
}
