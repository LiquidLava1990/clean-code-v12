//! Anthropic Messages-API backed [`crate::LlmClient`].
//!
//! Phase-5 ships:
//! - [`client::AnthropicClient`] — blocking-reqwest implementation with
//!   optional cache short-circuit.
//! - [`prompt_template`] — canonical slop / comment-drift / texture
//!   probe templates.
//! - [`wire`] — request/response serde structs for the Messages API.
//!
//! Re-exports at the crate root keep call-sites short:
//! `use cc_llm::AnthropicClient;`.

pub mod client;
pub mod prompt_template;
pub mod wire;

pub use client::{AnthropicClient, ANTHROPIC_VERSION, DEFAULT_BASE_URL, DEFAULT_MODEL};
pub use prompt_template::{
    render, COMMENT_DRIFT_TEMPLATE, PROMPT_TEMPLATE_VERSION, SLOP_PROBE_TEMPLATE,
    TEXTURE_PROBE_TEMPLATE,
};
pub use wire::{MessageContent, MessagesRequest, MessagesResponse, WireMessage};
