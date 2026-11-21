//! Cached LLM-judgment probes for Clean Code V12.
//!
//! The slop / comment-drift / rewrite-proposal probe families need a
//! reproducible LLM judgement layer with:
//!
//! 1. A deterministic content-addressed cache key
//!    ([`PromptCacheKey`]) so CI re-runs hit warm cache instead of
//!    burning tokens.
//! 2. A graceful disabled mode ([`DisabledLlm`]) so offline / no-key
//!    environments do not break the build.
//! 3. A thin trait surface ([`LlmClient`], [`CacheStore`]) so probes
//!    bind once and providers swap freely.
//!
//! # Phase 1 status
//!
//! Public traits + cache key derivation + [`DisabledLlm`] +
//! [`InMemoryCache`]. Real provider clients (Anthropic / `OpenAI` /
//! local llama.cpp) and the on-disk redb cache land in Phase 5.
//!
//! ```ignore
//! use cc_llm::{DisabledLlm, LlmClient, LlmError, Prompt};
//!
//! let client = DisabledLlm::new();
//! let prompt = Prompt::new(
//!     "You are a code reviewer. Is the following slop?\n{src}",
//!     vec!["a1b2c3".to_string(), "rule.slop_classifier".to_string()],
//! );
//! assert!(matches!(client.judge(&prompt), Err(LlmError::Disabled)));
//! ```
//!
//! # File map
//!
//! | Module     | Purpose                                  |
//! |------------|------------------------------------------|
//! | `client`   | [`LlmClient`] trait + [`DisabledLlm`]    |
//! | `prompt`   | [`Prompt`] + [`PromptCacheKey`]          |
//! | `response` | [`Judgment`], [`RewriteProposal`]        |
//! | `cache`    | [`CacheStore`] trait + [`InMemoryCache`] |
//! | `error`    | [`LlmError`]                             |

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod anthropic;
pub mod cache;
pub mod client;
pub mod error;
pub mod prompt;
pub mod response;

pub use anthropic::{
    AnthropicClient, COMMENT_DRIFT_TEMPLATE, PROMPT_TEMPLATE_VERSION, SLOP_PROBE_TEMPLATE,
    TEXTURE_PROBE_TEMPLATE,
};
pub use cache::{CacheStore, InMemoryCache};
pub use client::{DisabledLlm, LlmClient};
pub use error::{LlmError, Result};
pub use prompt::{Prompt, PromptCacheKey};
pub use response::{Judgment, RewriteProposal};

// TODO(phase-6): implement `RedbCache` for cross-run cache persistence.
// TODO(phase-5): add cost telemetry — every judge/rewrite call records
//   tokens-in/out + USD estimate into `cc-diagnostics` so operators can
//   budget LLM spend.
// TODO(phase-5): add streaming `judge_stream` / `rewrite_stream` so the
//   LSP probe family can show partial verdicts.

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_prompt() -> Prompt {
        Prompt::new(
            "Classify the following snippet as Clean or Slop.",
            vec!["abc123".into(), "rule.slop".into()],
        )
    }

    #[test]
    fn disabled_llm_returns_disabled_for_judge() {
        let client = DisabledLlm::new();
        let p = sample_prompt();
        assert!(matches!(client.judge(&p), Err(LlmError::Disabled)));
        assert!(matches!(client.rewrite(&p), Err(LlmError::Disabled)));
        assert!(!client.is_available());
    }

    #[test]
    fn prompt_cache_key_is_deterministic() {
        let p1 = sample_prompt();
        let p2 = sample_prompt();
        assert_eq!(p1.cache_key(), p2.cache_key());
    }

    #[test]
    fn prompt_cache_key_changes_with_inputs() {
        let p1 = sample_prompt();
        let p2 = Prompt::new(
            "Classify the following snippet as Clean or Slop.",
            vec!["DIFFERENT".into(), "rule.slop".into()],
        );
        assert_ne!(p1.cache_key(), p2.cache_key());
    }

    #[test]
    fn prompt_cache_key_input_order_matters() {
        let p1 = Prompt::new("t", vec!["a".into(), "b".into()]);
        let p2 = Prompt::new("t", vec!["b".into(), "a".into()]);
        assert_ne!(p1.cache_key(), p2.cache_key());
    }

    #[test]
    fn prompt_cache_key_hex_is_64_chars() {
        let key = sample_prompt().cache_key();
        let hex = key.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn prompt_cache_key_round_trips_to_finding_prompt_hash() {
        let key = sample_prompt().cache_key();
        let hash = key.to_prompt_hash();
        assert_eq!(hash.0, key.to_hex());
    }

    #[test]
    fn in_memory_cache_round_trip() {
        let cache = InMemoryCache::new();
        assert!(cache.is_empty());
        let key = sample_prompt().cache_key();
        assert!(cache.get(&key).is_none());

        let judgment = Judgment::Clean { confidence: 0.92 };
        cache.put(key, judgment.clone());
        assert_eq!(cache.len(), 1);

        let got = cache.get(&key).expect("just put");
        assert_eq!(got, judgment);
    }

    #[test]
    fn judgment_confidence_extractor() {
        assert!((Judgment::Clean { confidence: 0.5 }.confidence() - 0.5).abs() < f32::EPSILON);
        assert!(Judgment::Unsure.confidence().abs() < f32::EPSILON);
    }

    #[test]
    fn error_messages_include_action() {
        let s = LlmError::Disabled.to_string();
        assert!(s.contains("--no-llm") || s.contains("cc.toml"));
    }
}
