//! [`LlmClient`] trait + the [`DisabledLlm`] default.
//!
//! The default refuses every call with [`LlmError::Disabled`]. CI
//! pipelines and offline environments wire this without any config;
//! probe authors handle the error by skipping their probe gracefully.

use crate::error::LlmError;
use crate::prompt::Prompt;
use crate::response::{Judgment, RewriteProposal};

/// Probe-facing LLM interface.
///
/// Implementations MUST be `Send + Sync` so the kernel can share a
/// single `Arc<dyn LlmClient>` across rayon worker threads.
///
/// Every public method returns [`LlmError`] rather than `anyhow::Error`
/// so probes can match on `LlmError::Disabled` and fall back without
/// surfacing a hard failure.
pub trait LlmClient: Send + Sync {
    /// Submit a binary-classification prompt; receive a [`Judgment`].
    ///
    /// # Errors
    /// Returns [`LlmError::Disabled`] when the client has no provider
    /// configured, or [`LlmError::Transport`] / [`LlmError::InvalidResponse`]
    /// for runtime failures.
    fn judge(&self, prompt: &Prompt) -> Result<Judgment, LlmError>;

    /// Submit a rewrite prompt; receive a [`RewriteProposal`].
    ///
    /// # Errors
    /// Same shape as [`judge`].
    ///
    /// [`judge`]: LlmClient::judge
    fn rewrite(&self, prompt: &Prompt) -> Result<RewriteProposal, LlmError>;

    /// `true` when the client has a provider configured and is ready
    /// to serve requests. Probes consult this before issuing
    /// expensive prompts.
    fn is_available(&self) -> bool;
}

// ---------------------------------------------------------------------------
// DisabledLlm — Phase 1 default
// ---------------------------------------------------------------------------

/// No-op [`LlmClient`] that errors every call with
/// [`LlmError::Disabled`].
///
/// Wired at boot when no `[llm]` table is present in `cc.toml` or
/// when `--no-llm` is passed.
#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledLlm;

impl DisabledLlm {
    /// Construct a disabled client.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LlmClient for DisabledLlm {
    fn judge(&self, _prompt: &Prompt) -> Result<Judgment, LlmError> {
        Err(LlmError::Disabled)
    }

    fn rewrite(&self, _prompt: &Prompt) -> Result<RewriteProposal, LlmError> {
        Err(LlmError::Disabled)
    }

    fn is_available(&self) -> bool {
        false
    }
}
