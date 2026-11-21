//! [`EffectiveRule`] — a [`Rule`] resolved against per-repo config.
//!
//! Built by [`crate::RuleRegistry::apply_config`] from the rule's
//! defaults plus any matching [`cc_config::RuleConfig`] override. The
//! kernel iterates effective rules at scan time; each one carries
//! everything needed to run, plus pack provenance for diagnostics.

use cc_config::{Config, RuleConfig};
use cc_finding::Severity as FindingSeverity;

use crate::rule::Rule;

/// Pack-resolved, config-resolved view of a single rule.
///
/// All fields are owned references / values — no further lookups
/// needed at run time. The kernel ranks effective rules by
/// `severity` × `default_confidence` to schedule the cheap-and-loud
/// ones first.
#[derive(Clone)]
pub struct EffectiveRule {
    /// The rule itself.
    pub rule: &'static dyn Rule,
    /// Originating pack id — used in error messages and trace spans.
    pub pack_id: &'static str,
    /// Pack semver — same provenance as `pack_id`.
    pub pack_semver: &'static str,
    /// Resolved severity (default unless config downgraded it).
    pub severity: FindingSeverity,
    /// Whether the rule is enabled for this run. Tier-0 rules are
    /// always enabled — `cc-config::validate` rejects attempts to
    /// disable them at load time, so by the time a `Config` lands
    /// here we trust the value.
    pub enabled: bool,
    /// Per-rule config slice. Probes use this for thresholds + paths.
    pub config: RuleConfig,
}

impl std::fmt::Debug for EffectiveRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectiveRule")
            .field("rule_id", &self.rule.rule_id())
            .field("pack_id", &self.pack_id)
            .field("pack_semver", &self.pack_semver)
            .field("severity", &self.severity)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl EffectiveRule {
    /// Convenience: the rule's stable id.
    #[must_use]
    pub fn rule_id(&self) -> &'static str {
        self.rule.rule_id()
    }

    /// Build an effective rule from its components, applying any
    /// per-rule config override.
    #[must_use]
    pub(crate) fn resolve(
        rule: &'static dyn Rule,
        pack_id: &'static str,
        pack_semver: &'static str,
        config: &Config,
    ) -> Self {
        let rule_config = config
            .rules
            .get(rule.rule_id())
            .cloned()
            .unwrap_or_default();
        let severity = resolve_severity(rule.default_severity(), &rule_config);
        Self {
            rule,
            pack_id,
            pack_semver,
            severity,
            enabled: rule_config.enabled,
            config: rule_config,
        }
    }
}

/// Apply the per-rule severity override.
///
/// `cc-config` validates that overrides are downgrades only and that
/// Tier-0 rules cannot drop below `Required`; we trust that contract
/// here and simply translate the `cc-config` severity enum into the
/// canonical `cc-finding` severity.
fn resolve_severity(default: FindingSeverity, cfg: &RuleConfig) -> FindingSeverity {
    cfg.severity_override
        .map_or(default, finding_severity_from_config)
}

const fn finding_severity_from_config(sev: cc_config::Severity) -> FindingSeverity {
    match sev {
        cc_config::Severity::Blocker => FindingSeverity::Blocker,
        cc_config::Severity::Required => FindingSeverity::Required,
        cc_config::Severity::Nit => FindingSeverity::Nit,
    }
}
