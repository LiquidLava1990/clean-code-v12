//! `cc.convention.config_json_for_non_auth` — auth-only `config.json`.
//!
//! `config.json` may ONLY hold OAuth tokens / auth keys. Non-auth
//! values belong in YAML. The probe walks every [`NodeKind::File`]
//! whose basename is `config.json` AND whose path is inside a `platform/`
//! tree. It parses the source as JSON and flags every top-level key
//! whose value is plainly not an auth value.
//!
//! Auth-shaped values (any of these → skip):
//!
//! - String values with auth-token prefixes (`eyJ...` / `gho_...` /
//!   `ghp_...` / `ghu_...` / `ghs_...` / `ghr_...` / `Bearer ...`).
//! - Object values containing any of `access_token`, `refresh_token`,
//!   `client_secret`, `client_id`, `token`, `api_key`, or any key
//!   starting with `oauth_`.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};
use serde_json::Value as JsonValue;

use crate::helpers::{
    build_finding, is_layout_path, location_for_file, ConventionFindingBlueprint,
};

/// Family-24 probe R-CONVENTION-CONFIG-JSON-FOR-NON-AUTH.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConfigJsonForNonAuthRule;

const AUTH_OBJECT_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "client_secret",
    "client_id",
    "token",
    "api_key",
];

const AUTH_STRING_PREFIXES: &[&str] = &["eyJ", "gho_", "ghp_", "ghu_", "ghs_", "ghr_", "Bearer "];

impl Rule for ConfigJsonForNonAuthRule {
    fn rule_id(&self) -> &'static str {
        "cc.convention.config_json_for_non_auth"
    }
    fn category(&self) -> cc_finding::Category {
        cc_finding::Category::Convention
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "config.json carries non-auth keys — move them to YAML config"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            if !is_target_file(&path) {
                continue;
            }
            let bytes = ctx.source.get(path.as_path());
            scan_config_json(&path, bytes, &mut out);
        }
        out
    }
}

fn is_target_file(path: &Utf8PathBuf) -> bool {
    if !is_layout_path(path) {
        return false;
    }
    path.file_name() == Some("config.json")
}

fn scan_config_json(path: &Utf8PathBuf, bytes: &[u8], out: &mut Vec<Finding>) {
    let text = std::str::from_utf8(bytes).unwrap_or("");
    if text.trim().is_empty() {
        return;
    }
    let Ok(JsonValue::Object(map)) = serde_json::from_str::<JsonValue>(text) else {
        return;
    };
    for (key, value) in &map {
        if is_auth_shaped(key, value) {
            continue;
        }
        out.push(emit(path, key));
    }
}

fn is_auth_shaped(key: &str, value: &JsonValue) -> bool {
    if AUTH_OBJECT_KEYS.contains(&key) || key.starts_with("oauth_") {
        return true;
    }
    match value {
        JsonValue::String(s) => AUTH_STRING_PREFIXES.iter().any(|p| s.starts_with(p)),
        JsonValue::Object(obj) => obj
            .keys()
            .any(|k| AUTH_OBJECT_KEYS.contains(&k.as_str()) || k.starts_with("oauth_")),
        _ => false,
    }
}

fn emit(path: &Utf8PathBuf, key: &str) -> Finding {
    let location = location_for_file(path.clone(), 1);
    build_finding(ConventionFindingBlueprint {
        rule_id: "cc.convention.config_json_for_non_auth",
        severity: Severity::Required,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("`config.json` key `{key}` is not auth-shaped"),
        explanation: format!(
            "Layout convention: `config.json` carries OAuth tokens + auth \
             keys ONLY. The key `{key}` does not look like an auth value, \
             so it must move to YAML config. Mixing non-auth keys into \
             `config.json` violates the protected-secret boundary and \
             risks the file being checked into version control."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Move the key to the appropriate YAML config file (per-component \
             settings next to the component, system-wide settings in \
             `config/*.yaml`). Leave only OAuth tokens / \
             auth keys in `config.json`."
                .into(),
        ),
        snippet: format!("\"{key}\": …"),
        weight: 3,
    })
}
