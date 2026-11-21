//! `cc.compliance.gdpr_pattern` — user-data class missing the GDPR
//! method set (export / forget / delete / anonymize).
//!
//! # Phase-5 STUB
//!
//! Whole-class method-set comparison requires resolving the `AST_PARENT`
//! tree from each `Method` node back up to its owning `Class` and
//! aggregating per-class. The frontend's `Class` ↔ `Method` linkage is
//! not yet stable across all four supported languages — Python class
//! bodies surface methods inline, Rust impl-blocks live in a sibling
//! `Block`, Go uses receiver types, TypeScript ships methods as
//! `Method` children of `Class`. Until that surface stabilises this
//! probe deliberately emits zero findings; the registration test
//! confirms it is wired.
//!
//! TODO(future): wire whole-class method-set comparison once the
//! frontends agree on a canonical Class → Method walk.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-21 probe R-GDPR-PATTERN. Phase-5 stub — see module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct GdprPatternRule;

impl Rule for GdprPatternRule {
    fn rule_id(&self) -> &'static str {
        "cc.compliance.gdpr_pattern"
    }
    fn category(&self) -> Category {
        Category::Compliance
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.6)
    }
    fn description(&self) -> &'static str {
        "user-data class missing GDPR export / forget / delete / anonymize methods (Phase-5 stub)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // STUB: whole-class method-set comparison deferred — see module docs.
        Vec::new()
    }
}

/// Class-name fragments that suggest a class holds user data and is
/// therefore subject to GDPR right-to-be-forgotten obligations. Kept
/// public-crate so the wired implementation can reuse the table.
#[allow(dead_code)] // Reserved for the wired-up Phase-6 implementation.
pub(crate) const USER_DATA_CLASS_PATTERNS: &[&str] = &["user", "customer", "profile", "account"];

/// Methods that satisfy the GDPR right-to-be-forgotten contract. Any
/// of these on the class body silences the probe once it is wired.
#[allow(dead_code)] // Reserved for the wired-up Phase-6 implementation.
pub(crate) const GDPR_METHOD_NAMES: &[&str] =
    &["export_data", "delete_account", "forget_user", "anonymize"];
