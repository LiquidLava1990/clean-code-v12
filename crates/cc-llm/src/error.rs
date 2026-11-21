//! Errors emitted by `cc-llm`.
//!
//! Every variant follows R-ERR-ACTION: it states *what* went wrong
//! and *how* to fix it.

use thiserror::Error;

/// Errors raised by an [`LlmClient`].
///
/// [`LlmClient`]: crate::LlmClient
#[derive(Debug, Error)]
pub enum LlmError {
    /// LLM access is intentionally disabled (e.g. CI without an API
    /// key, or `--no-llm` flag). Probes catch this and degrade to
    /// static-only behaviour.
    #[error(
        "LLM client is disabled; \
         enable an LLM-judgment probe-pack via `cc.toml [llm] provider = ...` \
         and provide credentials, or run with `--no-llm` to suppress this probe family"
    )]
    Disabled,

    /// LLM provider returned an HTTP/transport error.
    #[error(
        "LLM provider transport failure: {detail}; \
         retry the run; if the failure persists, check provider status \
         and the credentials referenced in `cc.toml [llm]`"
    )]
    Transport {
        /// Provider-supplied detail (status code, timeout, etc.).
        detail: String,
    },

    /// LLM returned a payload that did not match the expected schema.
    #[error(
        "LLM response did not match expected schema: {detail}; \
         widen `prompt.template` to insist on JSON-only output \
         and retry, or pin the provider to a stricter model"
    )]
    InvalidResponse {
        /// What was wrong with the payload.
        detail: String,
    },

    /// Internal cache-store failure (lock poisoned, disk full).
    #[error(
        "LLM cache `{store}` failed: {detail}; \
         clear the cache directory referenced in `cc.toml [llm.cache]` \
         and retry"
    )]
    Cache {
        /// Cache type-name for triage.
        store: &'static str,
        /// Underlying detail.
        detail: String,
    },

    /// Provider client constructed but missing credentials or required
    /// configuration. Distinct from [`LlmError::Disabled`] which is the
    /// *intentional* off switch.
    #[error(
        "LLM provider not configured: {reason}; \
         set the missing credential in the environment (e.g. `ANTHROPIC_API_KEY=...`) \
         or pick a different `[llm] provider` in `cc.toml`"
    )]
    NotConfigured {
        /// What configuration is missing.
        reason: String,
    },

    /// Provider HTTP call returned a non-success status.
    #[error(
        "LLM provider HTTP {status}: {body}; \
         inspect the body for a provider error code, then retry the run \
         once the upstream issue clears (rate-limit, model availability, etc.)"
    )]
    HttpError {
        /// HTTP status code returned by the provider.
        status: u16,
        /// Raw body (truncated by callers if needed) for triage.
        body: String,
    },

    /// JSON serialisation / deserialisation around a provider call failed.
    #[error(
        "LLM JSON encode/decode failure: {source}; \
         re-run with `RUST_LOG=cc_llm=debug` to capture the offending payload, \
         then file a bug if the schema in `prompt_template.rs` looks stale"
    )]
    JsonError {
        /// Underlying serde error.
        #[from]
        source: serde_json::Error,
    },
}

/// Crate-wide convenience [`Result`] alias.
pub type Result<T> = std::result::Result<T, LlmError>;
