//! Self-host gate: every public-facing error message contains both a *what*
//! and a *how* segment.

use cc_cpg_store::StoreError;

fn assert_actionable(err: &StoreError) {
    let msg = format!("{err}");
    assert!(msg.contains("Fix:"), "error missing actionable hint: {msg}");
    // "what" segment: the message must start with a non-empty descriptor
    // before "Fix:". (No bare "Fix: ..." messages.)
    let split: Vec<_> = msg.splitn(2, "Fix:").collect();
    assert_eq!(split.len(), 2, "no Fix: marker in {msg}");
    assert!(!split[0].trim().is_empty(), "no 'what' segment in {msg}");
}

#[test]
fn schema_mismatch_message_actionable() {
    let err = StoreError::SchemaMismatch {
        path: camino::Utf8PathBuf::from("/tmp/cpg.redb"),
        found: 9,
        expected: 1,
    };
    assert_actionable(&err);
}

#[test]
fn integrity_message_actionable() {
    let err = StoreError::Integrity {
        detail: "test".into(),
    };
    assert_actionable(&err);
}

#[test]
fn schema_unset_message_actionable() {
    let err = StoreError::SchemaUnset {
        path: camino::Utf8PathBuf::from("/tmp/cpg.redb"),
    };
    assert_actionable(&err);
}
