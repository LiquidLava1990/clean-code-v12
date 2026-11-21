//! `cc-fingerprint` — per-repo statistical style fingerprint for Clean Code
//! V12.
//!
//! Downstream wave-2 rules consume this fingerprint to flag *drift outliers*
//! rather than absolute violations. For example: a `camelCase` identifier in
//! a 95%-snake_case repo is flagged; a `camelCase` identifier in a mixed
//! repo is not.
//!
//! # Workflow
//!
//! 1. Walk the repo, lifting each file into a [`cc_cpg::CpgWriteBatch`].
//! 2. Roll each batch into a [`FingerprintBuilder`] via
//!    [`FingerprintBuilder::add_file`].
//! 3. Call [`FingerprintBuilder::finalize`] once at end-of-scan to obtain a
//!    [`Fingerprint`].
//! 4. Pass the [`Fingerprint`] to wave-2 rules (naming-drift,
//!    error-vocabulary, layering, test-style).
//!
//! # Public surface
//!
//! - [`FingerprintBuilder`] — incremental builder.
//! - [`Fingerprint`] — finalized struct (`Serialize + Deserialize`).
//! - [`NamingDistribution`] / [`NamingStyle`] — per-kind naming stats.
//! - [`ErrorPatternMap`] — repo-wide error class taxonomy.
//! - [`LayerGraph`] — observed import graph.
//! - [`TestStyleProfile`] — test-file conventions.
//! - [`FingerprintError`] — actionable errors per R-ERR-ACTION.
//!
//! See `crates/cc-rules/src/context.rs` for the public-API placeholder
//! (`cc_rules::ProjectFingerprint`) — this crate ships the richer
//! `cc_fingerprint::Fingerprint` that internal wave-2 rules consume.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod builder;
pub mod error;
pub mod errors;
pub mod fingerprint;
pub mod imports;
pub mod naming;
pub mod test_style;

pub use builder::FingerprintBuilder;
pub use error::{FingerprintError, FingerprintResult};
pub use errors::ErrorPatternMap;
pub use fingerprint::{Fingerprint, SampleSize};
pub use imports::LayerGraph;
pub use naming::{NamingDistribution, NamingStyle, StyleCounts};
pub use test_style::TestStyleProfile;
