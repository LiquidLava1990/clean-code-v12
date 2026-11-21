//! `cc-rules-secrets` — Family 19 (config + secrets) probe pack.
//!
//! Phase 2 + Phase 8 + Phase 10 of Clean Code V12. Ships twenty-one
//! probes:
//!
//! - [`secret_in_code`] — high-entropy / known-prefix secret literals.
//! - [`dead_env_var`] — env-var lookups whose name appears nowhere else.
//! - [`dead_config_key`] — stub (Phase 3 wires the fingerprint config-graph).
//! - [`env_drift`] — stub (Phase 3 cross-batch drift detection).
//! - [`weak_crypto`] — `md5` / `sha1` / `DES` / `RC4` call sites.
//! - [`dotenv_lint`] — `.env` file syntactic hygiene.
//! - [`aws_token_pattern`] — `AKIA…` / `ASIA…` access keys (gitleaks).
//! - [`private_key_pem`] — `-----BEGIN [...] PRIVATE KEY-----` headers.
//! - [`gcp_api_key`] — `AIza…` Google Cloud API keys.
//! - [`github_pat`] — `ghp_…` / `github_pat_…` PATs.
//! - [`slack_token`] — `xox[baprs]-…` Slack tokens.
//! - [`stripe_key`] — `sk_live_…` / `pk_live_…` Stripe live keys.
//! - [`generic_api_key_assignment`] — heuristic `api_key|secret|token =
//!   "<long-string>"` shape.
//! - [`requests_no_verify`] — Python `requests.<verb>(…, verify=False)`
//!   (Bandit B501).
//! - [`subprocess_shell_true`] — Python `subprocess.<fn>("...",
//!   shell=True)` (Bandit B602).
//! - [`urllib_no_verify`] — Python `ssl._create_unverified_context` /
//!   `verify_mode = ssl.CERT_NONE` (Bandit B323).
//! - [`gosec_hardcoded_creds_var`] — Go credential-shaped `var/const`
//!   initialised with a long literal (gosec G101).
//! - [`gosec_weak_random`] — Go `math/rand` for security-sensitive
//!   randomness (gosec G404).
//! - [`gosec_md5_sha1`] — Go md5/sha1 used for security purposes
//!   (gosec G401/G405).
//! - [`gosec_des_rc4`] — Go DES / RC4 cipher constructor (gosec
//!   G401/G402).
//! - [`gosec_tls_insecure_skip_verify`] — Go `tls.Config{
//!   InsecureSkipVerify: true }` (gosec G402).
//!
//! See [`BuiltinSecretsPack`] for the registered [`cc_rules::RulePack`].
//!
//! # Self-host gate
//!
//! Every public item carries doc comments (`deny(missing_docs)`), no
//! function exceeds 50 LOC, no nesting deeper than three levels, and
//! the crate forbids `unsafe_code`. The pack dogfoods the Tier-0
//! forever rules + Family 19's own `weak_crypto` (no md5/sha1 here).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aws_token_pattern;
pub mod dead_config_key;
pub mod dead_env_var;
pub mod dotenv_lint;
pub mod env_drift;
pub mod gcp_api_key;
pub mod generic_api_key_assignment;
pub mod github_pat;
pub mod gosec_des_rc4;
pub mod gosec_hardcoded_creds_var;
pub mod gosec_md5_sha1;
pub mod gosec_tls_insecure_skip_verify;
pub mod gosec_weak_random;
mod helpers;
mod pack;
pub mod private_key_pem;
pub mod requests_no_verify;
pub mod secret_in_code;
pub mod slack_token;
pub mod stripe_key;
pub mod subprocess_shell_true;
pub mod urllib_no_verify;
pub mod weak_crypto;

#[cfg(test)]
mod tests;

pub use pack::BuiltinSecretsPack;

/// Re-export of the canonical pack id, useful for downstream tests.
pub const PACK_ID: &str = BuiltinSecretsPack::PACK_ID;
