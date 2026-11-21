//! Baseline-diff sink behavioural test.

mod common;

use std::collections::HashSet;

use cc_finding::{BaselineDiffSink, FindingSink, TtySink};
use common::sample_finding;

#[test]
fn baseline_drops_known_findings() {
    let known = sample_finding("fn known() { 1 }");
    let new = sample_finding("fn brand_new() { 2 }");

    let mut baseline = HashSet::new();
    baseline.insert(known.suppress_key);

    let inner = TtySink::new(Box::new(Vec::<u8>::new()), false);
    let mut diff = BaselineDiffSink::new(inner, baseline);

    diff.emit(known).unwrap();
    diff.emit(new).unwrap();

    assert_eq!(diff.suppressed_count(), 1);
    let summary = Box::new(diff).finish().unwrap();
    assert_eq!(summary.total, 1);
}
