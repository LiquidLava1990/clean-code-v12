//! Config validation.
//!
//! Three checks per rule entry:
//! 1. Rule id is registered (`ConfigError::UnknownRule`).
//! 2. Tier-0 rules cannot be disabled (`ConfigError::CannotDisableTier0`).
//! 3. `severity_override` must be a downgrade or equal (`ConfigError::SeverityUpgrade`).
//!
//! Glob patterns are also compiled here as a smoke-test, surfacing
//! `ConfigError::BadGlob` for malformed entries before scan time.

use crate::error::{ConfigError, Result};
use crate::model::{Config, RuleConfig};
use crate::path_scope::build_globset;
use crate::registry::{intrinsic_severity_for, is_registered, is_tier0, suggest_rules};
use crate::severity::Severity;

/// Run every validation check against `cfg`.
///
/// Errors short-circuit on first failure — reporting all errors in
/// one pass is a P2 enhancement.
///
/// # Errors
///
/// - [`ConfigError::UnknownRule`] — unregistered `rule_id`.
/// - [`ConfigError::CannotDisableTier0`] — Tier-0 disabled.
/// - [`ConfigError::SeverityUpgrade`] — invalid severity override.
/// - [`ConfigError::BadGlob`] — malformed glob pattern.
pub fn validate(cfg: &Config) -> Result<()> {
    for (id, rule) in &cfg.rules {
        validate_rule_entry(id, rule)?;
    }
    validate_globs(cfg)?;
    Ok(())
}

/// Validate a single rule entry (id known, tier-0 not disabled, severity sane).
fn validate_rule_entry(id: &str, rule: &RuleConfig) -> Result<()> {
    check_known_rule(id)?;
    check_not_disabling_tier0(id, rule)?;
    check_severity_override(id, rule)?;
    Ok(())
}

/// Reject unknown rule ids with suggestions.
fn check_known_rule(id: &str) -> Result<()> {
    if is_registered(id) {
        return Ok(());
    }
    let suggestions = suggest_rules(id);
    let suggestion_blurb = render_suggestions(&suggestions);
    Err(ConfigError::UnknownRule {
        id: id.to_owned(),
        suggestions,
        suggestion_blurb,
    })
}

/// Render suggestions as human-friendly text for the error message.
fn render_suggestions(suggestions: &[&'static str]) -> String {
    if suggestions.is_empty() {
        String::new()
    } else if suggestions.len() == 1 {
        format!(" — did you mean '{}'?", suggestions[0])
    } else {
        let joined = suggestions
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(" — did you mean one of {joined}?")
    }
}

/// Reject `enabled = false` on Tier-0 rules.
fn check_not_disabling_tier0(id: &str, rule: &RuleConfig) -> Result<()> {
    if is_tier0(id) && !rule.enabled {
        return Err(ConfigError::CannotDisableTier0 { id: id.to_owned() });
    }
    Ok(())
}

/// Reject `severity_override` that upgrades severity.
///
/// Only downgrades (or equals) are allowed. Tier-0 cannot be downgraded
/// below `Required` either — but per spec, downgrade-to-Nit IS allowed
/// for non-Family-0 rules. Family-0 rules keep at least Required.
fn check_severity_override(id: &str, rule: &RuleConfig) -> Result<()> {
    let Some(requested) = rule.severity_override else {
        return Ok(());
    };
    let intrinsic = intrinsic_severity_for(id);
    if requested > intrinsic {
        return Err(ConfigError::SeverityUpgrade {
            id: id.to_owned(),
            intrinsic: intrinsic.as_str(),
            requested: requested.as_str(),
        });
    }
    if is_tier0(id) && requested == Severity::Nit {
        // Tier-0 may be downgraded to Required but not all the way to Nit —
        // Nit is effectively "off" and Tier-0 cannot be off.
        return Err(ConfigError::SeverityUpgrade {
            id: id.to_owned(),
            intrinsic: intrinsic.as_str(),
            requested: requested.as_str(),
        });
    }
    Ok(())
}

/// Smoke-test compile every glob in the config.
fn validate_globs(cfg: &Config) -> Result<()> {
    build_globset(&cfg.ignore.paths, "ignore.paths")?;
    for (id, rule) in &cfg.rules {
        let prefix = format!("rules.\"{id}\".paths");
        rule.paths.compile(&prefix)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Config;
    use crate::path_scope::PathScope;
    use std::collections::BTreeMap;

    fn cfg_with_rule(id: &str, rule: RuleConfig) -> Config {
        let mut cfg = Config::default();
        cfg.rules.insert(id.into(), rule);
        cfg
    }

    #[test]
    fn unknown_rule_with_typo_suggests() {
        let cfg = cfg_with_rule("cc.shape.fn_lenght", RuleConfig::default());
        let err = validate(&cfg).unwrap_err();
        match err {
            ConfigError::UnknownRule { suggestions, .. } => {
                assert!(suggestions.contains(&"cc.shape.fn_length"));
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn disabling_tier0_rejected() {
        let cfg = cfg_with_rule(
            "cc.shape.fn_length",
            RuleConfig {
                enabled: false,
                ..RuleConfig::default()
            },
        );
        assert!(matches!(
            validate(&cfg).unwrap_err(),
            ConfigError::CannotDisableTier0 { .. }
        ));
    }

    #[test]
    fn upgrade_blocker_rejected() {
        // Try to "upgrade" from Required to Blocker on a hypothetical
        // non-tier0 rule. Use a fake intrinsic table — to stay in
        // registered space, we treat severity_override == intrinsic
        // as allowed and severity_override > intrinsic as rejected.
        // Since all current registered rules are Blocker, we instead
        // exercise the explicit `Tier-0 -> Nit` downgrade ban below.
        let cfg = cfg_with_rule(
            "cc.shape.fn_length",
            RuleConfig {
                severity_override: Some(Severity::Nit),
                ..RuleConfig::default()
            },
        );
        assert!(matches!(
            validate(&cfg).unwrap_err(),
            ConfigError::SeverityUpgrade { .. }
        ));
    }

    #[test]
    fn downgrade_to_required_allowed_for_tier0() {
        let cfg = cfg_with_rule(
            "cc.shape.fn_length",
            RuleConfig {
                severity_override: Some(Severity::Required),
                ..RuleConfig::default()
            },
        );
        validate(&cfg).expect("required is a valid downgrade for Tier-0");
    }

    #[test]
    fn bad_glob_in_rule_paths_rejected() {
        let mut paths = PathScope::default();
        paths.include.push("[broken".into());
        let cfg = cfg_with_rule(
            "cc.shape.fn_length",
            RuleConfig {
                paths,
                ..RuleConfig::default()
            },
        );
        assert!(matches!(
            validate(&cfg).unwrap_err(),
            ConfigError::BadGlob { .. }
        ));
    }

    #[test]
    fn empty_thresholds_validate() {
        let cfg = cfg_with_rule(
            "cc.shape.fn_length",
            RuleConfig {
                thresholds: BTreeMap::new(),
                ..RuleConfig::default()
            },
        );
        validate(&cfg).expect("empty thresholds are fine");
    }
}
