//! JSON-RPC 2.0 envelope types + canned error helpers.
//!
//! MCP rides on JSON-RPC 2.0. The spec defines a small, fixed schema
//! (request: `jsonrpc`, `id`, `method`, `params`; response: `jsonrpc`,
//! `id`, plus exactly one of `result` / `error`). We model that here so
//! the server module stays readable.
//!
//! IDs are `serde_json::Value` because the spec allows string, number,
//! or null. We never compare IDs — the server echoes them back verbatim.

use serde::{Deserialize, Serialize};

/// JSON-RPC `parse error` code.
pub const CODE_PARSE_ERROR: i32 = -32_700;
/// JSON-RPC `invalid request` code.
pub const CODE_INVALID_REQUEST: i32 = -32_600;
/// JSON-RPC `method not found` code.
pub const CODE_METHOD_NOT_FOUND: i32 = -32_601;
/// JSON-RPC `invalid params` code.
pub const CODE_INVALID_PARAMS: i32 = -32_602;
/// JSON-RPC `internal error` code.
pub const CODE_INTERNAL_ERROR: i32 = -32_603;

/// Inbound JSON-RPC request envelope.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    /// Always the literal `"2.0"` per spec.
    pub jsonrpc: String,
    /// Caller-supplied id; absent for notifications. We don't dispatch
    /// notifications differently in V12 — we simply omit the response
    /// when `id` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    /// Method name, e.g. `"tools/list"`.
    pub method: String,
    /// Method-specific parameters. Always an object in MCP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// Outbound JSON-RPC response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Echoes `request.id`. `null` for parse errors where we never read
    /// the id.
    pub id: serde_json::Value,
    /// Success payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error payload — mutually exclusive with `result`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Numeric error code per JSON-RPC spec.
    pub code: i32,
    /// Human-readable summary.
    pub message: String,
    /// Optional structured payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Build a success response that echoes `id`.
#[must_use]
pub fn success_response(id: serde_json::Value, result: serde_json::Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_owned(),
        id,
        result: Some(result),
        error: None,
    }
}

/// Build an error response that echoes `id`.
#[must_use]
pub fn error_response(
    id: serde_json::Value,
    code: i32,
    message: impl Into<String>,
) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_owned(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data: None,
        }),
    }
}

/// Canned `parse error` response (id is null because the request was
/// unparseable).
#[must_use]
pub fn parse_error(detail: impl Into<String>) -> JsonRpcResponse {
    error_response(
        serde_json::Value::Null,
        CODE_PARSE_ERROR,
        format!(
            "parse error: {}. Fix: send a single JSON-RPC 2.0 object per line.",
            detail.into()
        ),
    )
}

/// Canned `method not found` response.
#[must_use]
pub fn method_not_found(id: serde_json::Value, method: &str) -> JsonRpcResponse {
    error_response(
        id,
        CODE_METHOD_NOT_FOUND,
        format!(
            "method `{method}` not found. Fix: call one of `initialize`, `tools/list`, `tools/call`.",
        ),
    )
}

/// Canned `invalid params` response.
#[must_use]
pub fn invalid_params(id: serde_json::Value, detail: impl Into<String>) -> JsonRpcResponse {
    error_response(
        id,
        CODE_INVALID_PARAMS,
        format!("invalid params: {}", detail.into()),
    )
}
