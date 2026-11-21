//! [`AnthropicClient`] — real [`LlmClient`] implementation against the
//! Anthropic Messages API.
//!
//! # Design choice: blocking `reqwest`
//!
//! [`crate::LlmClient`] is a synchronous trait. Two ways to back it
//! with HTTP:
//!
//! 1. `reqwest::blocking::Client` — runs each request on the calling
//!    thread, no runtime spin-up cost.
//! 2. Async `reqwest::Client` wrapped in a `tokio::runtime::Runtime`
//!    that calls `block_on(...)` per request.
//!
//! cc-llm picks (1). Probes are already invoked from rayon worker
//! threads so nothing higher up in the stack is async. Spinning a
//! per-call runtime would add latency and surface
//! "runtime-inside-runtime" panics if a future caller wraps cc-kernel
//! in their own tokio context. Blocking reqwest sidesteps both.
//!
//! Trade-off: long-running streaming responses (Phase 6) will need a
//! second async-only entry point — added then, not bolted on now.
//!
//! # Cache short-circuit
//!
//! When a [`crate::CacheStore`] is wired and its `get` returns `Some`,
//! the HTTP path is **completely** skipped. This is what makes
//! `from_env` (no key) + `with_cache` still useful for warm-cache CI:
//! cache hits never call HTTP, so the missing key never matters.

use std::sync::Arc;
use std::time::Duration;

use crate::cache::CacheStore;
use crate::client::LlmClient;
use crate::error::LlmError;
use crate::prompt::Prompt;
use crate::response::{Judgment, RewriteProposal};

use super::wire::{MessagesRequest, MessagesResponse, WireMessage};

/// Default model id for slop / drift / texture probes — Anthropic's
/// cheapest + fastest tier as of Phase-5 design freeze.
pub const DEFAULT_MODEL: &str = "claude-haiku-4-5-20251001";

/// Default API base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Anthropic Messages API version header value. Pinned so a server-side
/// schema change cannot silently break parsing.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Per-request token cap. Probe responses are one JSON line.
const MAX_TOKENS: u32 = 256;

/// HTTP timeout. Slop probes are short; anything longer is a stall.
const HTTP_TIMEOUT_SECS: u64 = 30;

/// Real [`LlmClient`] backed by the Anthropic Messages API with an
/// optional [`CacheStore`] short-circuit.
///
/// Construct via [`AnthropicClient::from_env`]; layer cache + model via
/// the builder methods. Missing `ANTHROPIC_API_KEY` is **not** an error
/// — the client constructs but [`AnthropicClient::is_available`]
/// returns `false` and live calls return [`LlmError::NotConfigured`].
/// Cache hits still resolve so warm-cache CI works keyless.
pub struct AnthropicClient {
    /// API key from `ANTHROPIC_API_KEY` at construction time. `None`
    /// means HTTP calls return [`LlmError::NotConfigured`].
    api_key: Option<String>,
    /// API base URL. Override for staging / proxy.
    base_url: String,
    /// Anthropic model id.
    model: String,
    /// Optional cache. When wired, hits skip HTTP entirely.
    cache: Option<Arc<dyn CacheStore>>,
    /// Reusable blocking HTTP client. Connection pool + TLS state
    /// amortised across calls.
    http: reqwest::blocking::Client,
}

impl std::fmt::Debug for AnthropicClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `api_key` is intentionally surfaced only as a presence-bool
        // (R-05 secret hygiene); `http` is opaque. `finish_non_exhaustive`
        // signals both.
        f.debug_struct("AnthropicClient")
            .field("api_key_present", &self.api_key.is_some())
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("cache_wired", &self.cache.is_some())
            .finish_non_exhaustive()
    }
}

impl AnthropicClient {
    /// Construct from environment.
    ///
    /// Reads `ANTHROPIC_API_KEY`. Missing key is preserved as `None`
    /// (see struct-level docs).
    ///
    /// # Panics
    /// Never. The blocking client builder errors are caught and the
    /// build falls back to `Client::new()`.
    #[must_use]
    pub fn from_env() -> Self {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty());
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|err| {
                tracing::warn!(
                    error = %err,
                    "AnthropicClient: builder failed, falling back to default client"
                );
                reqwest::blocking::Client::new()
            });
        Self {
            api_key,
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            cache: None,
            http,
        }
    }

    /// Wire a cache store. Cache hits short-circuit the HTTP path.
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<dyn CacheStore>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Override the default model id.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Programmatically set the API key (for tests, embedded callers,
    /// or any context where the key arrives by means other than the
    /// `ANTHROPIC_API_KEY` env var). Empty / whitespace-only input
    /// clears the key.
    #[must_use]
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        let key = api_key.into();
        self.api_key = if key.trim().is_empty() {
            None
        } else {
            Some(key)
        };
        self
    }

    /// Clear any configured API key. Useful for tests that need the
    /// "no key" path without mutating process env.
    #[must_use]
    pub fn without_api_key(mut self) -> Self {
        self.api_key = None;
        self
    }

    /// Override the API base URL (test fixtures, proxy).
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Borrow the configured model id.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// `true` iff an API key was found at construction time.
    #[must_use]
    pub const fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    /// Render the prompt into a single user-message string.
    ///
    /// Inputs are appended after the template separated by `\n---\n`
    /// markers so the model sees them in the same order they appear in
    /// the cache key.
    fn render_user_message(prompt: &Prompt) -> String {
        let mut s = String::with_capacity(prompt.template.len() + 128);
        s.push_str(prompt.template);
        for input in &prompt.fingerprint_inputs {
            s.push_str("\n---\n");
            s.push_str(input);
        }
        s
    }

    /// Send one Messages request and return the raw text content.
    fn send_messages(&self, prompt: &Prompt) -> Result<String, LlmError> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| LlmError::NotConfigured {
                reason: "ANTHROPIC_API_KEY not set in environment".to_string(),
            })?;
        let body = MessagesRequest {
            model: self.model.clone(),
            max_tokens: MAX_TOKENS,
            messages: vec![WireMessage {
                role: "user".to_string(),
                content: Self::render_user_message(prompt),
            }],
            temperature: 0.0,
        };
        let url = format!("{}/v1/messages", self.base_url);
        let response = self
            .http
            .post(&url)
            .header("x-api-key", api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .map_err(|err| LlmError::Transport {
                detail: format!("{}: {err}", type_name_short(&err)),
            })?;
        let status = response.status();
        let raw = response.text().map_err(|err| LlmError::Transport {
            detail: format!("read body: {err}"),
        })?;
        if !status.is_success() {
            return Err(LlmError::HttpError {
                status: status.as_u16(),
                body: truncate(&raw, 1024),
            });
        }
        let parsed: MessagesResponse = serde_json::from_str(&raw)?;
        let text = parsed.text();
        if text.is_empty() {
            return Err(LlmError::InvalidResponse {
                detail: "no text content blocks in response".to_string(),
            });
        }
        Ok(text)
    }
}

/// Parse a one-line JSON judgement payload into a [`Judgment`].
///
/// Accepts the schema documented in
/// [`crate::anthropic::prompt_template`]. Trims whitespace and a
/// leading `` ```json `` fence the model might have added despite the
/// instructions.
pub(crate) fn parse_judgment(raw: &str) -> Result<Judgment, LlmError> {
    let cleaned = strip_code_fence(raw.trim());
    let value: serde_json::Value = serde_json::from_str(cleaned)?;
    let verdict = value
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LlmError::InvalidResponse {
            detail: format!("missing `verdict` field in payload (len={})", cleaned.len()),
        })?;
    match verdict {
        "clean" => Ok(Judgment::Clean {
            confidence: extract_confidence(&value),
        }),
        "slop" => {
            let reason = value
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            Ok(Judgment::Slop {
                confidence: extract_confidence(&value),
                reason,
            })
        }
        "unsure" => Ok(Judgment::Unsure),
        other => Err(LlmError::InvalidResponse {
            detail: format!("unknown verdict `{other}`"),
        }),
    }
}

/// Pull `confidence` and clamp into `[0.0, 1.0]`. Missing → `0.0`.
fn extract_confidence(value: &serde_json::Value) -> f32 {
    let raw = value
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    let clamped = raw.clamp(0.0, 1.0);
    // Casting a clamped f64 in [0,1] to f32 is lossless enough for
    // probe scoring; clippy::cast_possible_truncation is a non-issue.
    #[allow(clippy::cast_possible_truncation)]
    {
        clamped as f32
    }
}

/// Strip a leading ```` ```json ```` / ```` ``` ```` fence and trailing
/// ```` ``` ```` if present. Idempotent on un-fenced input.
fn strip_code_fence(s: &str) -> &str {
    let s = s.strip_prefix("```json").unwrap_or(s);
    let s = s.strip_prefix("```").unwrap_or(s);
    let s = s.trim_start_matches('\n').trim();
    s.strip_suffix("```").unwrap_or(s).trim()
}

/// Truncate a string to `max` chars, appending `…` if cut.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut out = s.chars().take(max).collect::<String>();
    out.push('…');
    out
}

/// Short type-name for logging without a full path.
fn type_name_short<T>(_: &T) -> &'static str {
    let n = std::any::type_name::<T>();
    n.rsplit("::").next().unwrap_or(n)
}

impl LlmClient for AnthropicClient {
    fn judge(&self, prompt: &Prompt) -> Result<Judgment, LlmError> {
        let key = prompt.cache_key();
        if let Some(cache) = self.cache.as_ref() {
            if let Some(hit) = cache.get(&key) {
                tracing::debug!(prompt_hash = %key.to_hex(), "AnthropicClient: cache hit");
                return Ok(hit);
            }
        }
        let raw = self.send_messages(prompt)?;
        let judgment = parse_judgment(&raw)?;
        if let Some(cache) = self.cache.as_ref() {
            cache.put(key, judgment.clone());
        }
        Ok(judgment)
    }

    fn rewrite(&self, _prompt: &Prompt) -> Result<RewriteProposal, LlmError> {
        // Phase-5 ships only judge. Rewrite lands with the structured
        // tool-use schema in Phase-6 alongside streaming.
        Err(LlmError::InvalidResponse {
            detail: "rewrite() not yet implemented for AnthropicClient (Phase 6)".to_string(),
        })
    }

    fn is_available(&self) -> bool {
        self.api_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clean_verdict() {
        let out = parse_judgment(r#"{"verdict":"clean","confidence":0.9}"#).expect("parse");
        match out {
            Judgment::Clean { confidence } => {
                assert!((confidence - 0.9).abs() < 1e-3);
            }
            other => panic!("expected Clean, got {other:?}"),
        }
    }

    #[test]
    fn parse_slop_verdict_with_reason() {
        let out = parse_judgment(r#"{"verdict":"slop","confidence":0.8,"reason":"filler"}"#)
            .expect("parse");
        match out {
            Judgment::Slop { reason, .. } => assert_eq!(reason, "filler"),
            other => panic!("expected Slop, got {other:?}"),
        }
    }

    #[test]
    fn parse_unsure_verdict() {
        let out = parse_judgment(r#"{"verdict":"unsure"}"#).expect("parse");
        assert!(matches!(out, Judgment::Unsure));
    }

    #[test]
    fn parse_strips_code_fence() {
        let out = parse_judgment("```json\n{\"verdict\":\"clean\",\"confidence\":0.5}\n```")
            .expect("parse");
        assert!(matches!(out, Judgment::Clean { .. }));
    }

    #[test]
    fn parse_rejects_unknown_verdict() {
        let err = parse_judgment(r#"{"verdict":"maybe"}"#).expect_err("should fail");
        assert!(matches!(err, LlmError::InvalidResponse { .. }));
    }

    #[test]
    fn confidence_is_clamped() {
        let v: serde_json::Value = serde_json::from_str(r#"{"confidence":2.5}"#).expect("ser");
        assert!((extract_confidence(&v) - 1.0).abs() < f32::EPSILON);
        let v: serde_json::Value = serde_json::from_str(r#"{"confidence":-1.0}"#).expect("ser");
        assert!(extract_confidence(&v).abs() < f32::EPSILON);
    }

    #[test]
    fn truncate_appends_ellipsis() {
        let s = truncate("abcdef", 3);
        assert_eq!(s, "abc…");
    }
}
