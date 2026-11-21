//! `cc.config.dotenv_lint` — lint `.env` files for syntactic hygiene
//! issues.
//!
//! Walks every batch whose enclosing [`NodeKind::File`] path ends in
//! `.env` (including environment-suffixed variants like `.env.dev` or
//! `.env.production`) and flags:
//!
//! - Duplicate keys.
//! - Keys with whitespace surrounding `=` (`FOO = bar` violates
//!   POSIX-shell semantics that most loaders emulate).
//! - Unquoted values containing whitespace.
//! - Lowercase env-var names (POSIX convention is uppercase).

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{build_finding, location_for_file, SecretsFindingBlueprint};

/// Family-19 probe R-DOTENV-LINT.
#[derive(Debug, Default, Clone, Copy)]
pub struct DotenvLintRule;

impl Rule for DotenvLintRule {
    fn rule_id(&self) -> &'static str {
        "cc.config.dotenv_lint"
    }
    fn category(&self) -> Category {
        Category::Config
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.9)
    }
    fn description(&self) -> &'static str {
        ".env file has duplicate keys, surrounding spaces, lowercase names, or unquoted whitespace"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for node in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(raw) = string_prop(ctx.batch, node.id, "path") else {
                continue;
            };
            let path = Utf8PathBuf::from(raw);
            if !is_dotenv_path(&path) {
                continue;
            }
            let bytes = ctx.source.get(path.as_path());
            let text = std::str::from_utf8(bytes).unwrap_or("");
            collect_findings(text, &path, &mut out);
        }
        out
    }
}

fn is_dotenv_path(path: &Utf8PathBuf) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    name == ".env" || name.starts_with(".env.")
}

fn collect_findings(text: &str, path: &Utf8PathBuf, out: &mut Vec<Finding>) {
    let mut seen_keys: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for (idx, raw) in text.lines().enumerate() {
        let lineno = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(key_end) = find_assignment(raw) else {
            continue;
        };
        let key_raw = &raw[..key_end];
        let value_raw = raw[key_end..].trim_start_matches('=');
        if let Some(finding) = lint_line(path, lineno, key_raw, value_raw, &mut seen_keys) {
            out.push(finding);
        }
    }
}

fn find_assignment(raw: &str) -> Option<usize> {
    raw.bytes().position(|b| b == b'=')
}

fn lint_line(
    path: &Utf8PathBuf,
    lineno: u32,
    key_raw: &str,
    value_raw: &str,
    seen: &mut std::collections::BTreeMap<String, u32>,
) -> Option<Finding> {
    let key_trimmed = key_raw.trim();
    if key_trimmed.is_empty() {
        return None;
    }
    if let Some(reason) = classify_key(key_raw, key_trimmed, seen) {
        return Some(emit(path, lineno, key_trimmed, reason));
    }
    classify_value(value_raw).map(|reason| emit(path, lineno, key_trimmed, reason))
}

fn classify_key(
    key_raw: &str,
    key_trimmed: &str,
    seen: &mut std::collections::BTreeMap<String, u32>,
) -> Option<&'static str> {
    if key_raw != key_trimmed {
        return Some("whitespace around `=`");
    }
    if key_trimmed.chars().any(|c| c.is_ascii_lowercase()) {
        return Some("lowercase env-var name");
    }
    let count = seen.entry(key_trimmed.to_owned()).or_insert(0);
    *count = count.saturating_add(1);
    if *count > 1 {
        return Some("duplicate key");
    }
    None
}

fn classify_value(value_raw: &str) -> Option<&'static str> {
    let v = value_raw.trim_start();
    if v.is_empty() {
        return None;
    }
    let starts_quoted = v.starts_with('"') || v.starts_with('\'');
    if starts_quoted {
        return None;
    }
    if v.contains(' ') {
        return Some("unquoted value contains whitespace");
    }
    None
}

fn emit(path: &Utf8PathBuf, lineno: u32, key: &str, reason: &'static str) -> Finding {
    let location = location_for_file(path.clone(), lineno);
    build_finding(SecretsFindingBlueprint {
        rule_id: "cc.config.dotenv_lint",
        category: Category::Config,
        severity: Severity::Required,
        confidence: Confidence::new(0.9),
        location,
        headline: format!(".env line {lineno}: {reason} on key `{key}`"),
        explanation: format!(
            ".env files are parsed by every dotenv loader (python-dotenv, dotenv-rs, \
             go's godotenv, node's dotenv) with subtly different rules. The issue \
             on line {lineno} ({reason}) silently changes the parsed value or \
             collides with another key in some loaders."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Use UPPER_SNAKE_CASE for keys, no whitespace around `=`, and quote any \
             value that contains whitespace. Deduplicate repeated keys."
                .into(),
        ),
        snippet: format!("{key}=…"),
        weight: 1,
    })
}
