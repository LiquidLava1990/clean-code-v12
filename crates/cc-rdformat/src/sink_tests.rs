//! Unit tests for [`crate::sink::RdJsonSink`].

use cc_finding::{FindingSink, Severity};

use crate::doc::SourceMeta;
use crate::sink::RdJsonSink;
use crate::test_support::sample_finding;

#[test]
fn streaming_emit_one_line_per_finding() {
    let mut sink = RdJsonSink::new(Vec::<u8>::new(), SourceMeta::clean_code_v12());
    for rule in [
        "cc.shape.fn_length",
        "cc.shape.file_length",
        "cc.slop.duplication",
    ] {
        let finding = sample_finding(rule, Severity::Required);
        sink.emit(finding).unwrap();
    }
    let buf = sink.into_writer();
    let text = std::str::from_utf8(&buf).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    for line in lines {
        // Each line must parse as JSON on its own.
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v.get("message").is_some());
        assert!(v.get("location").is_some());
        assert!(v.get("severity").is_some());
    }
}

#[test]
fn finish_returns_summary_counters() {
    let buf: Vec<u8> = Vec::new();
    let mut sink = Box::new(RdJsonSink::new(buf, SourceMeta::clean_code_v12()));
    sink.emit(sample_finding("cc.shape.fn_length", Severity::Blocker))
        .unwrap();
    sink.emit(sample_finding("cc.shape.file_length", Severity::Required))
        .unwrap();
    let summary = sink.finish().unwrap();
    assert_eq!(summary.total, 2);
    assert!(summary.has_blocker());
}
