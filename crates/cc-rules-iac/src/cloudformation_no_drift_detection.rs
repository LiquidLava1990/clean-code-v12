//! `cc.iac.cloudformation_no_drift_detection` — Phase-6 STUB.
//!
//! Detecting CFN-stack drift requires reading actual CloudFormation
//! stack metadata + the deployed template, which V12 does not have. The
//! rule is registered so the pack id space is reserved; it returns an
//! empty `Vec<Finding>` until a CFN-aware backend lands.
//!
//! TODO(phase-7): wire CFN-stack analysis once the cloud-resource
//! frontend exists.

use cc_finding::{Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-29 probe R-IAC-CFN-NO-DRIFT (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct CloudformationNoDriftDetectionRule;

impl Rule for CloudformationNoDriftDetectionRule {
    fn rule_id(&self) -> &'static str {
        "cc.iac.cloudformation_no_drift_detection"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Deploy
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "stub — CFN drift detection awaits Phase-7 cloud-resource frontend"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        Vec::new()
    }
}
