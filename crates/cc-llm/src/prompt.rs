//! [`Prompt`] + deterministic [`PromptCacheKey`] derivation.
//!
//! The cache key is **content-addressed**: same template + same
//! fingerprint inputs → identical key → cache hit, regardless of host,
//! day, or LLM provider. This is what makes [`crate::CacheStore`]
//! reproducible across CI runs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use cc_finding::PromptHash;

/// A prompt envelope passed to an [`LlmClient`].
///
/// `template` is the static prompt skeleton (from a probe-pack
/// constants file). `fingerprint_inputs` is the ordered list of values
/// — e.g. file content hash, rule id, function name — that distinguish
/// one invocation of `template` from another.
///
/// Order matters: changing the order of inputs changes the cache key.
/// Probe authors should keep input order stable across releases or
/// risk a cache stampede.
///
/// [`LlmClient`]: crate::LlmClient
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    /// Static prompt skeleton (probe-pack constant).
    pub template: &'static str,

    /// Ordered list of inputs that make this invocation unique.
    pub fingerprint_inputs: Vec<String>,
}

impl Prompt {
    /// Construct a prompt.
    #[must_use]
    pub const fn new(template: &'static str, fingerprint_inputs: Vec<String>) -> Self {
        Self {
            template,
            fingerprint_inputs,
        }
    }

    /// Derive the deterministic cache key.
    ///
    /// SHA-256 over: `template` || `0x1F` || each `fingerprint_input`
    /// joined by `0x1F` (ASCII Unit Separator — chosen so newlines
    /// inside inputs cannot collide with the separator).
    #[must_use]
    pub fn cache_key(&self) -> PromptCacheKey {
        let mut hasher = Sha256::new();
        hasher.update(self.template.as_bytes());
        for input in &self.fingerprint_inputs {
            hasher.update([0x1F]);
            hasher.update(input.as_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        PromptCacheKey(bytes)
    }
}

/// 32-byte SHA-256 digest used as a cache key for one [`Prompt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PromptCacheKey(pub [u8; 32]);

impl PromptCacheKey {
    /// Hex-encoded form. Round-trips through [`cc_finding::PromptHash`]
    /// so cached judgments can be cross-referenced from a `Finding`'s
    /// fix proposal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in self.0 {
            // R-ERR-ACTION dogfood not relevant here — `format!` of a
            // u8 is infallible.
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }

    /// Bridge to the `cc-finding` prompt-hash type used by
    /// `FixProposal::Llm.prompt_hash`.
    #[must_use]
    pub fn to_prompt_hash(&self) -> PromptHash {
        PromptHash(self.to_hex())
    }
}
