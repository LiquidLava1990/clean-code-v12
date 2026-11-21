//! JSON-RPC dispatch + stdio I/O loop.
//!
//! [`handle_request`] is pure-data — it takes a parsed
//! [`JsonRpcRequest`] and returns a [`JsonRpcResponse`]. The stdio
//! adapter [`run_stdio`] wraps it with line-by-line framing.
//!
//! Every malformed input path returns a JSON-RPC error response — the
//! reader never crashes on bad input.

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::jsonrpc::{
    error_response, invalid_params, method_not_found, parse_error, success_response,
    JsonRpcRequest, JsonRpcResponse, CODE_INTERNAL_ERROR,
};
use crate::tools::{call_tool, list_tools};

/// MCP protocol version we advertise on `initialize`.
const PROTOCOL_VERSION: &str = "2025-03-26";

/// Dispatch a parsed JSON-RPC request to the right handler.
///
/// Returns an error response (never panics) for unknown methods or
/// malformed parameters.
#[must_use]
pub fn handle_request(req: JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.clone().unwrap_or(Value::Null);
    if req.jsonrpc != "2.0" {
        return error_response(
            id,
            crate::jsonrpc::CODE_INVALID_REQUEST,
            "jsonrpc must be \"2.0\". Fix: set the `jsonrpc` field to the literal \"2.0\".",
        );
    }
    match req.method.as_str() {
        "initialize" => success_response(id, build_initialize_result()),
        "initialized" | "notifications/initialized" => {
            // Spec-mandated notification — we just acknowledge.
            success_response(id, serde_json::json!({}))
        }
        "tools/list" => success_response(id, build_tools_list_result()),
        "tools/call" => handle_tools_call(id, req.params),
        "ping" => success_response(id, serde_json::json!({})),
        other => method_not_found(id, other),
    }
}

fn build_initialize_result() -> Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": "cc-mcp",
            "version": env!("CARGO_PKG_VERSION"),
        }
    })
}

fn build_tools_list_result() -> Value {
    let tools = list_tools();
    serde_json::json!({ "tools": tools })
}

fn handle_tools_call(id: Value, params: Option<Value>) -> JsonRpcResponse {
    let Some(params) = params else {
        return invalid_params(
            id,
            "tools/call requires `params`. Fix: pass `{name, arguments}`.",
        );
    };
    let Some(name) = params.get("name").and_then(|v| v.as_str()) else {
        return invalid_params(
            id,
            "tools/call requires `params.name` (string). Fix: pass e.g. `{\"name\":\"cc_check\"}`.",
        );
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let payload = call_tool(name, arguments);
    success_response(id, payload)
}

/// Read newline-delimited JSON-RPC requests from stdin, write responses
/// to stdout. Runs until stdin closes.
///
/// # Errors
///
/// Returns the first IO error encountered on stdin/stdout. Malformed
/// JSON frames are surfaced as JSON-RPC parse-error responses, not
/// returned errors — the loop keeps running.
pub async fn run_stdio() -> std::io::Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = reader.next_line().await? {
        let response = process_line(&line);
        if let Some(resp) = response {
            write_response(&mut stdout, &resp).await?;
        }
    }
    Ok(())
}

/// Parse a single line + dispatch. Returns `None` for notifications
/// (id absent) so the stdio loop knows to suppress the response.
fn process_line(line: &str) -> Option<JsonRpcResponse> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed: Result<JsonRpcRequest, _> = serde_json::from_str(trimmed);
    match parsed {
        Ok(req) => {
            let is_notification = req.id.is_none();
            let response = catch_internal_error(req);
            if is_notification {
                None
            } else {
                Some(response)
            }
        }
        Err(err) => Some(parse_error(err.to_string())),
    }
}

/// Wrap [`handle_request`] so that any panic inside a tool dispatcher
/// turns into an internal-error response instead of crashing the
/// stdio loop.
fn catch_internal_error(req: JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.clone().unwrap_or(Value::Null);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle_request(req))) {
        Ok(resp) => resp,
        Err(_) => error_response(
            id,
            CODE_INTERNAL_ERROR,
            "internal error: tool dispatcher panicked. Fix: file a bug with the input that caused this.",
        ),
    }
}

async fn write_response<W>(writer: &mut W, response: &JsonRpcResponse) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut serialised = serde_json::to_vec(response).map_err(std::io::Error::other)?;
    serialised.push(b'\n');
    writer.write_all(&serialised).await?;
    writer.flush().await?;
    Ok(())
}
