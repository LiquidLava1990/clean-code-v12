//! MCP tool descriptors + the `tools/call` dispatcher.
//!
//! Every shipped tool has a stable `name`, a one-line `description`,
//! and a JSON-Schema input descriptor. Claude Code reads these via
//! `tools/list` and presents them to the model.
//!
//! Implementation lives in sibling modules:
//!
//! - [`crate::check`]  — `cc_check`
//! - [`crate::rules`]  — `cc_list_rules`, `cc_get_rule`

use serde::Serialize;

use crate::check::run_cc_check;
use crate::rules::{run_cc_get_rule, run_cc_list_rules};

/// MCP tool descriptor — what `tools/list` returns per tool.
#[derive(Debug, Clone, Serialize)]
pub struct ToolDescriptor {
    /// Unique tool name. Becomes `tools/call::params.name`.
    pub name: String,
    /// One-line human description.
    pub description: String,
    /// JSON-Schema for the `arguments` payload.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// All tools shipped by this MCP server.
///
/// Order is stable (clients sometimes display tools in returned order).
#[must_use]
pub fn list_tools() -> Vec<ToolDescriptor> {
    vec![
        cc_check_descriptor(),
        cc_list_rules_descriptor(),
        cc_get_rule_descriptor(),
    ]
}

/// Dispatch `tools/call` to the right tool implementation.
///
/// Returns the `result.content` payload for an MCP `tools/call` reply
/// — i.e. the value that goes inside the JSON-RPC `result` field. On
/// argument validation failure, returns an MCP-shaped error payload
/// (`{ "isError": true, "content": [...] }`) — MCP servers signal tool
/// errors *inside* `result`, not via JSON-RPC `error`, so the model
/// can read the diagnostic.
#[must_use]
pub fn call_tool(name: &str, args: serde_json::Value) -> serde_json::Value {
    let outcome = dispatch(name, args);
    wrap_outcome(outcome)
}

/// Dispatch by name without yet wrapping in the MCP envelope.
fn dispatch(name: &str, args: serde_json::Value) -> Result<serde_json::Value, String> {
    match name {
        "cc_check" => run_cc_check(&args),
        "cc_list_rules" => run_cc_list_rules(),
        "cc_get_rule" => run_cc_get_rule(&args),
        other => Err(format!(
            "unknown tool `{other}`. Fix: call `tools/list` first to discover tools.",
        )),
    }
}

/// Wrap a tool outcome in the MCP `content` envelope. MCP returns
/// content as a list of `{type, text}` blocks; we serialise the
/// result as JSON inside one `text` block so the client model can
/// read it. The `isError` flag distinguishes success from failure.
fn wrap_outcome(outcome: Result<serde_json::Value, String>) -> serde_json::Value {
    let (text, is_error) = match outcome {
        Ok(value) => (value.to_string(), false),
        Err(message) => (message, true),
    };
    serde_json::json!({
        "content": [{
            "type": "text",
            "text": text,
        }],
        "isError": is_error,
    })
}

fn cc_check_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "cc_check".to_owned(),
        description:
            "Run all Clean Code V12 rule packs against a path on disk OR an inline source \
             snippet. Returns the list of findings (severity, rule_id, location, message)."
                .to_owned(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to a file or directory to scan."
                },
                "content": {
                    "type": "string",
                    "description": "Inline source text. Pair with `language` when used."
                },
                "language": {
                    "type": "string",
                    "enum": ["python", "typescript", "javascript", "go", "rust"],
                    "description": "Language for `content`. Required when `content` is set."
                }
            },
            "oneOf": [
                { "required": ["path"] },
                { "required": ["content", "language"] }
            ]
        }),
    }
}

fn cc_list_rules_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "cc_list_rules".to_owned(),
        description:
            "List every rule registered by Clean Code V12 (id, category, severity, description). \
             Use this to discover what rules exist before calling `cc_get_rule` for details."
                .to_owned(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
    }
}

fn cc_get_rule_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "cc_get_rule".to_owned(),
        description:
            "Return full metadata for a single rule by id (category, severity, confidence, \
             description, owning pack)."
                .to_owned(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "Stable rule slug, e.g. `cc.shape.fn_length`."
                }
            },
            "required": ["rule_id"],
            "additionalProperties": false
        }),
    }
}
