//! Self-sanity validator for [`SarifDocument`].
//!
//! Schema-level conformance is delegated to consumers (microsoft/sarif-tools,
//! GitHub code-scanning, etc.). This validator only checks the invariants
//! cc-sarif promises to its callers: required fields populated, level
//! enum membership, fingerprint hex format.

use crate::doc::{SarifDocument, SarifResult, SARIF_VERSION};
use crate::error::SarifValidationError;

const ACCEPTED_LEVELS: &[&str] = &["error", "warning", "note", "none"];

/// Validate a [`SarifDocument`].
///
/// # Errors
/// Returns the collected per-issue list when at least one rule fails.
/// Schema-level validation is the consumer's responsibility.
pub fn validate(doc: &SarifDocument) -> Result<(), Vec<SarifValidationError>> {
    let mut errors = Vec::new();
    check_version(doc, &mut errors);
    check_runs_present(doc, &mut errors);
    for (run_idx, run) in doc.runs.iter().enumerate() {
        check_driver_name(run_idx, run, &mut errors);
        for (res_idx, result) in run.results.iter().enumerate() {
            check_result(run_idx, res_idx, result, &mut errors);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn check_version(doc: &SarifDocument, out: &mut Vec<SarifValidationError>) {
    if doc.version != SARIF_VERSION {
        out.push(SarifValidationError::BadVersion {
            found: doc.version.clone(),
        });
    }
}

fn check_runs_present(doc: &SarifDocument, out: &mut Vec<SarifValidationError>) {
    if doc.runs.is_empty() {
        out.push(SarifValidationError::NoRuns);
    }
}

fn check_driver_name(run_idx: usize, run: &crate::doc::Run, out: &mut Vec<SarifValidationError>) {
    if run.tool.driver.name.trim().is_empty() {
        out.push(SarifValidationError::EmptyDriverName { run: run_idx });
    }
}

fn check_result(
    run_idx: usize,
    res_idx: usize,
    result: &SarifResult,
    out: &mut Vec<SarifValidationError>,
) {
    if result.rule_id.trim().is_empty() {
        out.push(SarifValidationError::EmptyRuleId {
            run: run_idx,
            result: res_idx,
        });
    }
    if !ACCEPTED_LEVELS.contains(&result.level.as_str()) {
        out.push(SarifValidationError::BadLevel {
            run: run_idx,
            result: res_idx,
            found: result.level.clone(),
        });
    }
    if result.locations.is_empty() {
        out.push(SarifValidationError::NoLocations {
            run: run_idx,
            result: res_idx,
        });
    }
    check_fingerprints(run_idx, res_idx, result, out);
}

fn check_fingerprints(
    run_idx: usize,
    res_idx: usize,
    result: &SarifResult,
    out: &mut Vec<SarifValidationError>,
) {
    for (key, value) in &result.partial_fingerprints {
        if !is_lowercase_hex(value) {
            out.push(SarifValidationError::BadFingerprint {
                run: run_idx,
                result: res_idx,
                key: key.clone(),
                value: value.clone(),
            });
        }
    }
}

fn is_lowercase_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_hex_accepts_valid() {
        assert!(is_lowercase_hex("deadbeef00"));
        assert!(is_lowercase_hex(&"a".repeat(64)));
    }

    #[test]
    fn lowercase_hex_rejects_uppercase() {
        assert!(!is_lowercase_hex("DEADBEEF"));
    }

    #[test]
    fn lowercase_hex_rejects_non_hex() {
        assert!(!is_lowercase_hex("zzz"));
        assert!(!is_lowercase_hex(""));
    }
}
