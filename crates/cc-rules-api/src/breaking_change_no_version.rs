//! `cc.api.breaking_change_no_version` — STUB.
//!
//! Detection requires a git-diff side-channel on `openapi.yaml` /
//! `*.proto` files: a removed field, a narrowed type, or a renamed
//! endpoint is only a "breaking change" relative to the previous
//! committed schema. The current kernel walks a single working-tree
//! snapshot with no history feed, so a heuristic on a single batch
//! would either mass-flag every edit or stay silent on real breaks.
//! The probe is registered so the pack count is stable, but
//! unconditionally returns an empty [`Vec`].
//!
//! TODO(phase-5): wire diff-aware `OpenAPI` / proto version-bump
//! check once the runner gains a git-history side-channel.

use cc_finding::{Category, Confidence, Finding, Severity};
use cc_rules::{Rule, RuleContext};

/// Family-9 probe R-API-BREAKING-CHANGE-NO-VERSION (stub).
#[derive(Debug, Default, Clone, Copy)]
pub struct BreakingChangeNoVersionRule;

impl Rule for BreakingChangeNoVersionRule {
    fn rule_id(&self) -> &'static str {
        "cc.api.breaking_change_no_version"
    }
    fn category(&self) -> Category {
        Category::Api
    }
    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.5)
    }
    fn description(&self) -> &'static str {
        "breaking OpenAPI / proto change without a version bump (Phase-4 stub)"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        // TODO(phase-5): wire diff-aware OpenAPI version-bump check.
        Vec::new()
    }
}
