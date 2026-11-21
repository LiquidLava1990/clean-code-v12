//! `cc_list_rules` and `cc_get_rule` tool implementations.
//!
//! Both tools share a freshly-built registry populated with the
//! default pack set so the listing mirrors what `cc check` would run.
//! We rebuild per call (cheap — pack registration is just pointer
//! copying) to keep the surface stateless. The pack-registration
//! plumbing lives in `crate::_packs` so this file is not a god
//! module of pack imports.

use cc_rules::{Rule, RuleRegistry};
use serde::Serialize;

use crate::_packs::register_default_packs;

/// Compact rule descriptor used by `cc_list_rules`.
///
/// Exposed (`pub`) because the JSON shape is part of the MCP wire
/// contract — clients deserialise these fields by name.
#[derive(Debug, Clone, Serialize)]
pub struct RuleSummary {
    /// Stable rule slug.
    pub rule_id: String,
    /// Top-level category (Debug-formatted enum name).
    pub category: String,
    /// Default severity (Debug-formatted enum name).
    pub severity: String,
    /// Default confidence (Debug-formatted enum name).
    pub confidence: String,
    /// One-line human description.
    pub description: String,
    /// Owning pack id, if any.
    pub pack_id: Option<String>,
}

/// Full rule detail used by `cc_get_rule`.
///
/// Exposed (`pub`) for the same wire-contract reason as [`RuleSummary`].
#[derive(Debug, Clone, Serialize)]
pub struct RuleDetail {
    /// Stable rule slug.
    pub rule_id: String,
    /// Top-level category (Debug-formatted enum name).
    pub category: String,
    /// Default severity (Debug-formatted enum name).
    pub default_severity: String,
    /// Default confidence (Debug-formatted enum name).
    pub default_confidence: String,
    /// One-line human description.
    pub description: String,
    /// Owning pack id, if any.
    pub pack_id: Option<String>,
    /// Owning pack semver, if any.
    pub pack_semver: Option<String>,
}

impl RuleSummary {
    fn from_rule(registry: &RuleRegistry, rule: &dyn Rule) -> Self {
        let pack_id = registry
            .pack_of(rule.rule_id())
            .map(|(id, _)| id.to_owned());
        Self {
            rule_id: rule.rule_id().to_owned(),
            category: format!("{:?}", rule.category()),
            severity: format!("{:?}", rule.default_severity()),
            confidence: format!("{:?}", rule.default_confidence()),
            description: rule.description().to_owned(),
            pack_id,
        }
    }
}

impl RuleDetail {
    fn from_rule(registry: &RuleRegistry, rule: &dyn Rule) -> Self {
        let (pack_id, pack_semver) = match registry.pack_of(rule.rule_id()) {
            Some((id, semver)) => (Some(id.to_owned()), Some(semver.to_owned())),
            None => (None, None),
        };
        Self {
            rule_id: rule.rule_id().to_owned(),
            category: format!("{:?}", rule.category()),
            default_severity: format!("{:?}", rule.default_severity()),
            default_confidence: format!("{:?}", rule.default_confidence()),
            description: rule.description().to_owned(),
            pack_id,
            pack_semver,
        }
    }
}

/// Implement the `cc_list_rules` tool.
///
/// # Errors
///
/// Returns `Err(message)` only if pack registration fails — exposed as
/// a tool-error envelope to the caller.
pub fn run_cc_list_rules() -> Result<serde_json::Value, String> {
    let registry = build_registry()?;
    let rules: Vec<RuleSummary> = registry
        .rules()
        .map(|rule| RuleSummary::from_rule(&registry, rule))
        .collect();
    Ok(serde_json::json!({
        "count": rules.len(),
        "rules": rules,
    }))
}

/// Implement the `cc_get_rule` tool.
///
/// # Errors
///
/// Returns `Err(message)` when `args` is malformed, the rule id is
/// missing, or the rule is not registered.
pub fn run_cc_get_rule(args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let rule_id = args
        .get("rule_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "missing `rule_id` (string). Fix: pass `{\"rule_id\":\"cc.shape.fn_length\"}`."
                .to_owned()
        })?;
    let registry = build_registry()?;
    let rule = registry.rule_by_id(rule_id).ok_or_else(|| {
        format!(
            "rule `{rule_id}` is not registered. Fix: call `cc_list_rules` to see available ids.",
        )
    })?;
    let detail = RuleDetail::from_rule(&registry, rule);
    Ok(serde_json::json!({ "rule": detail }))
}

/// Build a registry pre-loaded with every default pack.
fn build_registry() -> Result<RuleRegistry, String> {
    let mut registry = RuleRegistry::new();
    register_default_packs(&mut registry)?;
    Ok(registry)
}
