//! `cc-rules` — the universal probe contract for Clean Code V12.
//!
//! This crate ships only the abstractions:
//!
//! - [`Rule`] — what every probe implements.
//! - [`RulePack`] + [`RuleRegistry`] — registration, lookup, ABI gating.
//! - [`RuleContext`] — what every probe receives at run time.
//! - [`EffectiveRule`] — rule + resolved per-repo config + provenance.
//! - [`run_rule`] — panic-safe, traced, confidence-filtered executor.
//! - [`BuiltinPack`] — empty placeholder until `cc-rules-tier0` lands.
//!
//! Concrete rules live in `cc-rules-tier0` and downstream pack crates.
//!
//! # Foundation invariants
//!
//! - `KERNEL_API_VERSION = 1`. Bump on any breaking change to the
//!   [`Rule`] / [`RuleContext`] / [`RulePack`] surface.
//! - Tier-0 enable-disable validation is owned by `cc-config`. This
//!   crate trusts that contract and never re-checks it.
//! - The runner ([`run_rule`]) is the ONLY entry point the kernel
//!   should use to execute a rule. It enforces tracing, panic
//!   handling, and confidence thresholds in one place.
//!
//! # Self-host gate
//!
//! Every error message produced by this crate names *what* went wrong
//! and *how* to fix it (R-ERR-ACTION). Adding a new variant to
//! [`RegistryError`] without both halves is a regression.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod context;
mod effective;
mod error;
mod registry;
mod rule;
mod runner;

pub use context::{
    FileBackedSourceTable, InMemorySourceTable, KernelMeta, ProjectFingerprint, RuleContext,
    SourceTable,
};
pub use effective::EffectiveRule;
pub use error::{RegistryError, RegistryResult};
pub use registry::{BuiltinPack, RuleRegistry};
pub use rule::{Rule, RulePack, KERNEL_API_VERSION};
pub use runner::run_rule;

#[cfg(test)]
mod tests;
