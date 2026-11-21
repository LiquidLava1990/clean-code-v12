//! `cc-config` — parse, validate, and merge `.cc/config.toml`.
//!
//! This crate is the per-repo configuration kernel for Clean Code V12.
//! It owns:
//!
//! - The data model ([`Config`] + sub-structs).
//! - The hardcoded Tier-0 [`registry::RULE_REGISTRY`].
//! - Validation (Tier-0 cannot be disabled, severity overrides cannot upgrade).
//! - Layered merge semantics (`global -> user -> repo`).
//! - A `cc init` helper ([`load::write_default`]).
//!
//! # Quick start
//!
//! ```no_run
//! use camino::Utf8Path;
//! use cc_config::Config;
//!
//! let cfg = Config::load(Utf8Path::new(".cc/config.toml"))?;
//! # Ok::<(), cc_config::ConfigError>(())
//! ```
//!
//! # Forever rules atop
//!
//! Tier-0 (Family 0) rules are forced on. Setting
//! `[rules."cc.shape.fn_length"] enabled = false` is rejected at load
//! time with [`ConfigError::CannotDisableTier0`]. `severity_override`
//! may downgrade a non-Family-0 rule (Required -> Nit) but never
//! upgrade. Tier-0 rules cannot be downgraded all the way to Nit.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod load;
pub mod model;
pub mod path_scope;
pub mod registry;
pub mod severity;
pub mod validate;

pub use error::{ConfigError, Result};
pub use load::write_default;
pub use model::{
    BaselineConfig, BaselineMode, Config, FingerprintConfig, IgnoreConfig, ProjectConfig,
    RuleConfig, RuntimeConfig,
};
pub use path_scope::PathScope;
pub use registry::{
    intrinsic_severity_for, is_registered, is_tier0, suggest_rules, RULE_REGISTRY, TIER_0_RULES,
    TIER_0_RULE_IDS,
};
pub use severity::Severity;
pub use validate::validate;
