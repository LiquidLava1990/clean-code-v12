//! Snapshot test for the TTY sink output (no colour, deterministic).

mod common;

use cc_finding::TtySink;
use common::sample_finding;

#[test]
fn tty_sink_format_smoke() {
    let sink = TtySink::new(Box::new(Vec::<u8>::new()), false);
    let f = sample_finding("fn x() { 1 }");
    let rendered = sink.render(&f);
    insta::assert_snapshot!(rendered, @r###"
    [REQUIRED] cc.shape.fn_length: function exceeds 50 LOC
      --> src/foo.rs:10:4
      Long functions hide control flow and resist testing; extract by responsibility, not by size.
      docs: https://cleancode.dev/rules/fn-length
    "###);
}

#[test]
fn tty_sink_emits_summary() {
    use cc_finding::FindingSink;
    let mut sink = TtySink::new(Box::new(Vec::<u8>::new()), false);
    sink.emit(sample_finding("a")).unwrap();
    sink.emit(sample_finding("b")).unwrap();
    let summary = Box::new(sink).finish().unwrap();
    assert_eq!(summary.total, 2);
}
