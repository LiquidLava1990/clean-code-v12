//! `cc-mcp` — Model Context Protocol (MCP) server for Clean Code V12.
//!
//! Exposes Clean Code's lint kernel as MCP tools so MCP-aware clients
//! (Claude Code, Cursor, etc.) can discover and invoke probes natively.
//!
//! # Protocol surface (minimum viable)
//!
//! Only three JSON-RPC methods are implemented; everything else is
//! returned as `MethodNotFound`:
//!
//! - `initialize`     — protocol handshake.
//! - `tools/list`     — returns the [`ToolDescriptor`] list.
//! - `tools/call`     — dispatches into [`call_tool`].
//!
//! Frame format: newline-delimited JSON, one JSON-RPC object per line,
//! over stdin/stdout. The MCP spec also permits length-prefixed framing
//! but every shipping client supports NDJSON, so V12 hand-rolls only
//! that path.
//!
//! # Tools shipped
//!
//! | Tool            | Args                                  | Returns                  |
//! |-----------------|---------------------------------------|--------------------------|
//! | `cc_check`      | `{path}` or `{content,language}`      | `{findings: [Finding]}`  |
//! | `cc_list_rules` | `{}`                                  | `{rules: [{id, desc}]}`  |
//! | `cc_get_rule`   | `{rule_id}`                           | `{rule: {…}}`            |
//!
//! # Forever rules atop
//!
//! - File ≤1500 LOC, function ≤50 LOC, nesting ≤3.
//! - No `unwrap()` / `panic!()` outside tests.
//! - Malformed JSON-RPC input MUST yield an error response, never a
//!   crash. The stdin reader treats each line as an opaque frame.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod _packs;
pub mod check;
pub mod jsonrpc;
pub mod rules;
pub mod server;
pub mod tools;

pub use jsonrpc::{
    error_response, invalid_params, method_not_found, parse_error, success_response, JsonRpcError,
    JsonRpcRequest, JsonRpcResponse,
};
pub use server::{handle_request, run_stdio};
pub use tools::{call_tool, list_tools, ToolDescriptor};

#[cfg(test)]
mod tests;
