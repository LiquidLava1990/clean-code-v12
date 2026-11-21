//! Error types for `cc-config`.
//!
//! Every variant names *what* failed and *how* to fix it (R-ERR-ACTION).

use camino::Utf8PathBuf;
use thiserror::Error;

/// All errors surfaced by the `cc-config` crate.
///
/// Messages are intentionally actionable — every variant describes
/// the fault *and* the remediation step. This crate's errors are the
/// dogfood for `R-ERR-ACTION`; if any message lacks a "how to fix",
/// that is a bug.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// I/O error reading the config file.
    #[error(
        "could not read config at {path}: {source} — \
         create the file via `cc init` or pass --config <path>"
    )]
    Io {
        /// Path that failed to read.
        path: Utf8PathBuf,
        /// Underlying io error.
        #[source]
        source: std::io::Error,
    },

    /// I/O error writing a config (used by `write_default`).
    #[error(
        "could not write config to {path}: {source} — \
         check directory exists and is writable"
    )]
    WriteIo {
        /// Destination path.
        path: Utf8PathBuf,
        /// Underlying io error.
        #[source]
        source: std::io::Error,
    },

    /// TOML parse error.
    #[error(
        "config at {path} is not valid TOML: {source} — \
         compare to `examples/example.cc.toml` and fix the syntax"
    )]
    Parse {
        /// Path of the offending file.
        path: Utf8PathBuf,
        /// Underlying toml parse error.
        #[source]
        source: Box<toml::de::Error>,
    },

    /// Serialization (round-trip / `write_default`) error.
    #[error(
        "could not serialize config: {source} — \
         this is an internal bug; please file an issue with the offending struct"
    )]
    Serialize {
        /// Underlying toml serializer error.
        #[source]
        source: Box<toml::ser::Error>,
    },

    /// A Tier-0 (Family 0) rule was set to `enabled = false`.
    ///
    /// Family-0 rules are forced on by design — they protect the
    /// codebase from forever-rule regressions.
    #[error(
        "rule '{id}' is a Tier-0 forever rule and cannot be disabled — \
         remove `enabled = false` from [rules.\"{id}\"], or override its \
         severity downward instead (Required -> Nit). Use `cc explain {id}` \
         to see why this rule is mandatory."
    )]
    CannotDisableTier0 {
        /// The `rule_id` that was being disabled.
        id: String,
    },

    /// `severity_override` attempted an upgrade. Only downgrades are allowed.
    #[error(
        "rule '{id}' has severity_override = '{requested}' which is an UPGRADE \
         from '{intrinsic}' — only downgrades are allowed (Blocker -> Required, \
         Required -> Nit). Remove the override or pick a less-severe value."
    )]
    SeverityUpgrade {
        /// The `rule_id` with the bad override.
        id: String,
        /// Intrinsic (rule-defined) severity.
        intrinsic: &'static str,
        /// Requested override severity.
        requested: &'static str,
    },

    /// The `rule_id` is not registered. Suggests close matches.
    #[error(
        "rule '{id}' is unknown{suggestion_blurb} — \
         run `cc explain` for the full rule list, \
         or check for typos in [rules.\"{id}\"]."
    )]
    UnknownRule {
        /// The unknown `rule_id` (typo, removed, or third-party).
        id: String,
        /// Suggested close-match rule ids.
        suggestions: Vec<&'static str>,
        /// Pre-rendered suggestion blurb (`""` if none).
        suggestion_blurb: String,
    },

    /// A glob in `IgnoreConfig` or `PathScope` failed to compile.
    #[error(
        "invalid glob pattern '{pattern}' in {field}: {source} — \
         see https://docs.rs/globset for syntax (e.g. `vendor/**/*.go`)"
    )]
    BadGlob {
        /// Pattern that failed.
        pattern: String,
        /// Field name where the pattern lived (`ignore.paths`, `rules.X.paths.include`, ...).
        field: String,
        /// Underlying globset error.
        #[source]
        source: Box<globset::Error>,
    },
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, ConfigError>;
