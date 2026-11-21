//! `cc-rules-supplychain` — Family 32 (supply-chain attestation +
//! dependency hygiene) probe pack.
//!
//! Phase 6 of Clean Code V12. The OSS delta report (`OSS_LINTER_DELTA.md`)
//! flagged Family 7 (deps) coverage as thin compared to OSSF Scorecard
//! (18 signal checks), npm-audit, dependabot, renovate, and sigstore
//! policy checkers. This pack covers the highest-leverage Scorecard
//! signals plus GitHub Actions hygiene and Renovate-style version
//! pinning.
//!
//! Ten probes:
//!
//! - [`unpinned_action`] — `uses: <repo>@<ref>` where `<ref>` is not a
//!   40-char SHA-1 hex (Scorecard `Pinned-Dependencies`).
//! - [`dangerous_workflow_pr_target`] — `pull_request_target` plus a
//!   checkout of the PR head ref / sha (Scorecard `Dangerous-Workflow`).
//! - [`no_dependabot_config`] — manifests present but `.github/dependabot.yml`
//!   is missing.
//! - [`no_codeowners`] — repo lacks `CODEOWNERS`.
//! - [`no_security_md`] — repo lacks `SECURITY.md`.
//! - [`npm_outdated_majors`] — STUB; needs deps.dev API ingest.
//! - [`cargo_unpinned_git_dep`] — `Cargo.toml` `git = "..."` without
//!   `rev = "<hash>"`.
//! - [`npm_dangerous_install_script`] — `package.json` `preinstall` /
//!   `postinstall` / `install` script.
//! - [`docker_apk_no_pin`] — Dockerfile `apk add <pkg>` without `=<ver>`
//!   (Hadolint DL3018).
//! - [`action_version_skew`] — STUB; needs cross-branch workflow diff.
//!
//! See [`BuiltinSupplyChainPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod action_version_skew;
pub mod cargo_unpinned_git_dep;
pub mod dangerous_workflow_pr_target;
pub mod docker_apk_no_pin;
mod helpers;
pub mod no_codeowners;
pub mod no_dependabot_config;
pub mod no_security_md;
pub mod npm_dangerous_install_script;
pub mod npm_outdated_majors;
mod pack;
pub mod unpinned_action;

#[cfg(test)]
mod tests;

pub use pack::BuiltinSupplyChainPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinSupplyChainPack::PACK_ID;
