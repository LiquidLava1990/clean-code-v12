//! Configuration data model.
//!
//! Top-level [`Config`] mirrors the layout of `.cc/config.toml`. The
//! struct is `serde`-driven; defaults round-trip through TOML. See
//! `examples/example.cc.toml` for a fully-commented sample.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::path_scope::PathScope;
use crate::severity::Severity;

/// Top-level repo configuration.
///
/// Loaded from `.cc/config.toml` at the repo root. All fields default
/// to sensible Tier-0 values so an empty config is valid.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Project-level metadata.
    pub project: ProjectConfig,
    /// Per-rule overrides, keyed by `rule_id` (e.g. `"cc.shape.fn_length"`).
    pub rules: BTreeMap<String, RuleConfig>,
    /// Repo-wide path ignore list.
    pub ignore: IgnoreConfig,
    /// Baseline file + drift mode.
    pub baseline: BaselineConfig,
    /// Runtime-data ingest (L0 layer — Phase 1 stub).
    pub runtime: RuntimeConfig,
    /// Project fingerprint / drift detection.
    pub fingerprint: FingerprintConfig,
}

/// Project-scoped metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    /// Human-friendly name (defaults to the repo directory name).
    pub name: String,
    /// Optional language overrides — e.g. force `python` on a `.txt`
    /// fixture directory. Empty list = auto-detect via tree-sitter.
    pub languages: Vec<String>,
    /// Repo root marker file. Defaults to `.cc/config.toml` itself.
    pub marker: Option<String>,
}

/// Per-rule override block.
///
/// Defaults: enabled = true, no severity override, no thresholds, no
/// path scoping. Tier-0 rules MUST stay enabled (validated at load).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleConfig {
    /// Whether the rule runs at all. Family-0 rules cannot disable.
    pub enabled: bool,
    /// Optional severity downgrade. Upgrades are rejected by validation.
    pub severity_override: Option<Severity>,
    /// Rule-specific thresholds (e.g. `max_loc = 50`).
    pub thresholds: BTreeMap<String, toml::Value>,
    /// Per-rule include/exclude globs (overrides global ignore).
    pub paths: PathScope,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            severity_override: None,
            thresholds: BTreeMap::new(),
            paths: PathScope::default(),
        }
    }
}

/// Repo-wide ignore configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IgnoreConfig {
    /// Glob patterns to skip (e.g. `vendor/**`, `**/*.gen.ts`).
    pub paths: Vec<String>,
    /// Auto-detect generated files (`*.pb.go`, `*_pb2.py`, `*.gen.ts`).
    pub generated: bool,
    /// Skip vendored dirs (`vendor/`, `node_modules/`, `.venv/`, `target/`).
    pub vendored: bool,
    /// Additional file extensions to skip (e.g. `["snap", "lock"]`).
    pub extensions: Vec<String>,
}

impl Default for IgnoreConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            generated: true,
            vendored: true,
            extensions: vec!["lock".into(), "snap".into()],
        }
    }
}

/// Baseline file pointer + drift mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselineConfig {
    /// Path to the baseline file (relative to repo root).
    pub path: String,
    /// Drift detection mode.
    pub mode: BaselineMode,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            path: ".cc/baseline.json".into(),
            mode: BaselineMode::default(),
        }
    }
}

/// Baseline drift handling mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineMode {
    /// Findings whose `suppress_key` matches baseline entries are dropped.
    #[default]
    Suppress,
    /// All findings reported; baseline is informational only.
    Report,
    /// Strict — any new finding fails CI even if absent from baseline.
    Strict,
}

/// Runtime-data ingest opt-in (Phase 1 stub).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Whether to ingest pprof / OTLP profile data when available.
    pub ingest: bool,
    /// Optional path to a pprof file or OTLP endpoint URL.
    pub source: Option<String>,
}

/// Project fingerprint / drift detection thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FingerprintConfig {
    /// Path to the fingerprint file.
    pub path: String,
    /// Sigma threshold for drift detection (default 3.0 = 3σ outliers).
    pub drift_sigma: f32,
    /// Whether to refresh the fingerprint on every full scan.
    pub auto_refresh: bool,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            path: ".cc/fingerprint.json".into(),
            drift_sigma: 3.0,
            auto_refresh: true,
        }
    }
}
