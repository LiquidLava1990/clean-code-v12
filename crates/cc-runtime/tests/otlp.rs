//! Integration tests for [`OtlpRuntime`].

use std::sync::Arc;

use camino::Utf8Path;
use cc_runtime::{EmptyRuntime, MultiplexedRuntime, OtlpRuntime, RuntimeView};

const OTLP_FIXTURE: &str = r#"
{
  "resourceSpans": [
    {
      "scopeSpans": [
        {
          "spans": [
            {
              "name": "fallback_span_name",
              "startTimeUnixNano": "1000000000",
              "endTimeUnixNano": "1500000000",
              "attributes": [
                { "key": "code.function", "value": { "stringValue": "service.handle_request" } },
                { "key": "code.filepath", "value": { "stringValue": "/build/src/service.py" } }
              ]
            },
            {
              "name": "module.background_task",
              "startTimeUnixNano": "2000000000",
              "endTimeUnixNano": "2002000000",
              "attributes": [
                { "key": "code.filepath", "value": { "stringValue": "src/worker.py" } }
              ]
            }
          ]
        }
      ]
    }
  ]
}
"#;

/// Synthetic OTLP/JSON ingest resolves spans by `code.function`.
#[test]
fn otlp_parses_json_export() {
    let view = OtlpRuntime::from_bytes(OTLP_FIXTURE.as_bytes()).expect("OTLP JSON parses");
    assert!(view.is_loaded());
    assert!(view.entry_count() >= 2);

    let cost = view
        .cost_for_function(Utf8Path::new("src/service.py"), "service.handle_request")
        .expect("recorded function resolves");
    assert!((cost.cpu_seconds - 0.5).abs() < 1e-6);
    assert_eq!(cost.call_count, 1);
    assert!(cost.p99_latency_ms.is_some());
}

/// Spans missing `code.function` attribute fall back to span name.
#[test]
fn otlp_missing_code_function_attr() {
    let view = OtlpRuntime::from_bytes(OTLP_FIXTURE.as_bytes()).expect("OTLP JSON parses");
    let cost = view
        .cost_for_function(Utf8Path::new("src/worker.py"), "module.background_task")
        .expect("span-name fallback resolves");
    assert!((cost.cpu_seconds - 0.002).abs() < 1e-6);
}

/// `MultiplexedRuntime` returns the first `Some(_)` produced by any
/// constituent view, in push order.
#[test]
fn multiplexed_returns_first_some() {
    let empty: Arc<dyn RuntimeView> = Arc::new(EmptyRuntime::new());
    let otlp: Arc<dyn RuntimeView> =
        Arc::new(OtlpRuntime::from_bytes(OTLP_FIXTURE.as_bytes()).expect("parses"));

    let mut mux = MultiplexedRuntime::empty();
    mux.push(empty);
    mux.push(otlp);

    assert!(mux.is_loaded());
    assert_eq!(mux.len(), 2);

    let cost = mux
        .cost_for_function(Utf8Path::new("src/service.py"), "service.handle_request")
        .expect("multiplexer delegates to second view");
    assert!(cost.cpu_seconds > 0.0);

    // Unknown lookup returns None across all views.
    assert!(mux
        .cost_for_function(Utf8Path::new("nope.py"), "missing")
        .is_none());
}

/// Empty multiplexer is indistinguishable from `EmptyRuntime`.
#[test]
fn multiplexed_empty_behaves_like_empty_runtime() {
    let mux = MultiplexedRuntime::empty();
    assert!(!mux.is_loaded());
    assert!(mux.is_empty());
    assert!(mux
        .cost_for_function(Utf8Path::new("any.rs"), "any")
        .is_none());
    assert!(mux.cost_for_call_site(Utf8Path::new("any.rs"), 1).is_none());
}
