//! Offline integration tests for [`cc_llm::AnthropicClient`].
//!
//! These tests must NEVER hit the network. A live-network integration
//! test requires VCR-style cassettes + a recorded fixture; that lands
//! in Phase 6 once `wiremock` is approved as a dev-dep.
//!
//! Tests use [`AnthropicClient::without_api_key`] / `with_api_key`
//! rather than mutating `ANTHROPIC_API_KEY` directly because the
//! workspace forbids `unsafe_code` (and `std::env::set_var` is
//! `unsafe` from Rust 1.84+).

#![deny(missing_docs)]
#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;

use cc_llm::anthropic::prompt_template::render;
use cc_llm::{
    AnthropicClient, CacheStore, InMemoryCache, Judgment, LlmClient, LlmError, Prompt,
    SLOP_PROBE_TEMPLATE,
};

/// Build a stable test prompt — same template + inputs across tests so
/// cache keys collide deterministically.
fn sample_prompt() -> Prompt {
    Prompt::new(
        SLOP_PROBE_TEMPLATE,
        vec![
            "abc123".to_string(),
            "rule.slop".to_string(),
            "fn foo() { /* todo */ }".to_string(),
        ],
    )
}

/// 1. No API key -> `is_available` is false and live calls return
///    `LlmError::NotConfigured`.
#[test]
fn from_env_without_key_returns_unavailable() {
    let client = AnthropicClient::from_env().without_api_key();
    assert!(!client.is_available(), "no key -> not available");

    let prompt = sample_prompt();
    let err = client.judge(&prompt).expect_err("should error without key");
    assert!(
        matches!(err, LlmError::NotConfigured { .. }),
        "expected NotConfigured, got {err:?}"
    );
}

/// 2. Prompt-template render produces a string with all `{placeholders}`
///    substituted and no leftover braces.
#[test]
fn prompt_template_renders_with_inputs() {
    let rendered = render(
        SLOP_PROBE_TEMPLATE,
        &[
            ("rule_id", "slop.repeated_phrase"),
            ("snippet", "fn foo() {}"),
        ],
    );
    assert!(
        rendered.contains("Rule id: slop.repeated_phrase"),
        "rule id substituted: {rendered}"
    );
    assert!(
        rendered.contains("fn foo() {}"),
        "snippet substituted: {rendered}"
    );
    assert!(
        !rendered.contains("{rule_id}"),
        "no leftover rule_id placeholder"
    );
    assert!(
        !rendered.contains("{snippet}"),
        "no leftover snippet placeholder"
    );
}

/// 3. With a pre-populated cache, `judge` short-circuits the HTTP path
///    even when no API key is set — the cache hit returns the stored
///    Judgment with no error.
#[test]
fn cache_hit_skips_http() {
    let prompt = sample_prompt();
    let key = prompt.cache_key();

    let cache = Arc::new(InMemoryCache::new());
    let stored = Judgment::Clean { confidence: 0.77 };
    cache.put(key, stored.clone());

    let cache_dyn: Arc<dyn CacheStore> = cache;
    let client = AnthropicClient::from_env()
        .without_api_key()
        .with_cache(cache_dyn);

    let got = client
        .judge(&prompt)
        .expect("cache hit should short-circuit even with no key");
    assert_eq!(got, stored);
}
