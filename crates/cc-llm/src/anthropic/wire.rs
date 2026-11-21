//! Wire types for the Anthropic Messages API.
//!
//! These mirror the public Anthropic schema as of 2026-04. Only the
//! subset cc-llm needs is modelled — extra fields are ignored on
//! deserialise.
//!
//! Reference: <https://docs.anthropic.com/en/api/messages>

use serde::{Deserialize, Serialize};

/// One message in the rolling conversation. cc-llm only ever sends a
/// single `user` message per probe (no multi-turn).
#[derive(Debug, Clone, Serialize)]
pub struct WireMessage {
    /// `"user"` or `"assistant"`. cc-llm only sends `"user"`.
    pub role: String,
    /// User-supplied text. cc-llm sends a fully-rendered prompt template.
    pub content: String,
}

/// Outbound `POST /v1/messages` body.
#[derive(Debug, Clone, Serialize)]
pub struct MessagesRequest {
    /// Anthropic model identifier (e.g. `claude-haiku-4-5-20251001`).
    pub model: String,
    /// Hard cap on response tokens. cc-llm probes return one JSON line,
    /// so a small cap is correct.
    pub max_tokens: u32,
    /// Single-shot user message.
    pub messages: Vec<WireMessage>,
    /// Sampling temperature. cc-llm probes are classifier-style, so
    /// `0.0` for determinism.
    pub temperature: f32,
}

/// One block of content inside a `MessagesResponse`. Anthropic returns
/// content as an array of typed blocks; cc-llm only consumes
/// `type = "text"` blocks.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageContent {
    /// Plain text block — the only kind cc-llm reads.
    Text {
        /// The model-generated text.
        text: String,
    },
    /// Any other block kind (`tool_use`, `tool_result`, etc.). Captured so
    /// deserialisation does not fail on unfamiliar shapes.
    #[serde(other)]
    Unknown,
}

/// Inbound `POST /v1/messages` body.
#[derive(Debug, Clone, Deserialize)]
pub struct MessagesResponse {
    /// Anthropic message id (logged on transport failure).
    #[serde(default)]
    pub id: String,
    /// `"end_turn"` on a clean completion.
    #[serde(default)]
    pub stop_reason: Option<String>,
    /// Ordered content blocks.
    pub content: Vec<MessageContent>,
}

impl MessagesResponse {
    /// Concatenate every `Text` block in order. Returns the empty
    /// string if there are no text blocks (caller treats that as
    /// `LlmError::InvalidResponse`).
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        for block in &self.content {
            if let MessageContent::Text { text } = block {
                out.push_str(text);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialises_text_block() {
        let raw = r#"{
            "id": "msg_01",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "hello"}]
        }"#;
        let parsed: MessagesResponse = serde_json::from_str(raw).expect("valid");
        assert_eq!(parsed.text(), "hello");
    }

    #[test]
    fn ignores_unknown_block_types() {
        let raw = r#"{
            "content": [
                {"type": "text", "text": "a"},
                {"type": "tool_use", "id": "x", "name": "y", "input": {}},
                {"type": "text", "text": "b"}
            ]
        }"#;
        let parsed: MessagesResponse = serde_json::from_str(raw).expect("valid");
        assert_eq!(parsed.text(), "ab");
    }

    #[test]
    fn request_serialises_all_fields() {
        let req = MessagesRequest {
            model: "claude-haiku-4-5-20251001".into(),
            max_tokens: 64,
            messages: vec![WireMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            temperature: 0.0,
        };
        let s = serde_json::to_string(&req).expect("ser");
        assert!(s.contains("\"model\":\"claude-haiku-4-5-20251001\""));
        assert!(s.contains("\"max_tokens\":64"));
        assert!(s.contains("\"role\":\"user\""));
    }
}
