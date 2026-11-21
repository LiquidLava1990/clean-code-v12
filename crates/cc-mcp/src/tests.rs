//! Unit tests for the MCP server.

use serde_json::json;

use crate::jsonrpc::JsonRpcRequest;
use crate::server::handle_request;
use crate::tools::{call_tool, list_tools};

#[test]
fn tools_list_returns_at_least_three_tools() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: Some(json!(1)),
        method: "tools/list".to_owned(),
        params: None,
    };
    let resp = handle_request(req);
    assert!(
        resp.error.is_none(),
        "tools/list returned error: {:?}",
        resp.error
    );
    let result = resp.result.expect("tools/list response missing result");
    let tools = result
        .get("tools")
        .and_then(|v| v.as_array())
        .expect("result.tools missing or not an array");
    assert!(
        tools.len() >= 3,
        "expected ≥3 tools, got {}: {:?}",
        tools.len(),
        tools,
    );

    let names: Vec<_> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    for expected in ["cc_check", "cc_list_rules", "cc_get_rule"] {
        assert!(
            names.contains(&expected),
            "missing tool `{expected}` in {names:?}",
        );
    }

    // Sanity: list_tools() free function matches the dispatched view.
    let direct = list_tools();
    assert_eq!(direct.len(), tools.len());
}

#[test]
fn cc_list_rules_returns_non_empty_rule_set() {
    let payload = call_tool("cc_list_rules", json!({}));
    assert_eq!(
        payload.get("isError").and_then(|v| v.as_bool()),
        Some(false),
        "cc_list_rules returned tool-error: {payload}",
    );
    let text = payload
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .expect("content[0].text missing");
    let parsed: serde_json::Value = serde_json::from_str(text).expect("inner payload not JSON");
    let rules = parsed
        .get("rules")
        .and_then(|r| r.as_array())
        .expect("rules array missing");
    assert!(
        !rules.is_empty(),
        "expected ≥1 rule across the default pack set, got 0",
    );
    // Cross-crate wiring sanity: every rule has a non-empty id and
    // an owning pack.
    for rule in rules {
        let id = rule.get("rule_id").and_then(|v| v.as_str()).unwrap_or("");
        assert!(!id.is_empty(), "rule with empty rule_id: {rule}");
        assert!(
            rule.get("pack_id").and_then(|v| v.as_str()).is_some(),
            "rule `{id}` missing pack_id",
        );
    }
}

#[test]
fn cc_check_runs_over_inline_python_snippet() {
    let snippet = "def add(a, b):\n    return a + b\n\nprint(add(1, 2))\n";
    let args = json!({ "content": snippet, "language": "python" });
    let payload = call_tool("cc_check", args);
    let is_error = payload
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    assert!(!is_error, "cc_check tool-error: {payload}");
    let text = payload
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .expect("content[0].text missing");
    let parsed: serde_json::Value = serde_json::from_str(text).expect("inner payload not JSON");
    // `findings` may be empty; the contract is that the field exists
    // and is an array — exercises the cross-crate scan path.
    let findings = parsed
        .get("findings")
        .and_then(|f| f.as_array())
        .expect("findings array missing");
    let count = parsed
        .get("count")
        .and_then(|c| c.as_u64())
        .expect("count missing");
    assert_eq!(findings.len() as u64, count);
}

#[test]
fn malformed_jsonrpc_yields_method_not_found() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: Some(json!("abc")),
        method: "nonexistent/method".to_owned(),
        params: None,
    };
    let resp = handle_request(req);
    assert!(
        resp.error.is_some(),
        "expected error, got: {:?}",
        resp.result
    );
    let err = resp.error.expect("error missing");
    assert_eq!(err.code, crate::jsonrpc::CODE_METHOD_NOT_FOUND);
}

#[test]
fn initialize_returns_protocol_version_and_server_info() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: Some(json!(7)),
        method: "initialize".to_owned(),
        params: Some(json!({})),
    };
    let resp = handle_request(req);
    assert!(resp.error.is_none(), "initialize errored: {:?}", resp.error);
    let result = resp.result.expect("initialize result missing");
    assert!(result.get("protocolVersion").is_some());
    let server_info = result.get("serverInfo").expect("serverInfo missing");
    assert_eq!(
        server_info.get("name").and_then(|v| v.as_str()),
        Some("cc-mcp"),
    );
}
