//! Integration tests for the [`cc_score`] engine.
//!
//! Tests are derived directly from the spec — see
//! `crates/cc-score/SPEC.md`. They cover:
//!
//! 1. Empty stream → 100/100.
//! 2. Single Blocker @ confidence 1.0 → 90.
//! 3. Single Blocker @ confidence 0.5 → 95 (ceil(5.0)).
//! 4. 10 Blockers @ 1.0 → 40 (capped at `blocker_cap`=60).
//! 5. 5 Required + 5 Nits → 85.
//! 6. 6 same-category findings → category-overweight kicks in.
//! 7. Determinism — two runs over the same slice produce byte-identical
//!    JSON (snapshotted via `expect_test`).

#![allow(clippy::missing_panics_doc)]

mod common;

use cc_finding::{Category, Severity};
use cc_score::{DeductionSource, ScoreEngine};
use common::{finding_with, finding_with_category};
use expect_test::expect;

#[test]
fn empty_findings_scores_100() {
    let engine = ScoreEngine::standard();
    let report = engine.score(&[]);

    assert_eq!(report.score, 100);
    assert!(report.deductions.is_empty());
    assert_eq!(report.finding_counts.blocker, 0);
    assert_eq!(report.finding_counts.required, 0);
    assert_eq!(report.finding_counts.nit, 0);
    assert!(report.finding_counts.by_category.is_empty());
}

#[test]
fn one_blocker_certain_scores_90() {
    let engine = ScoreEngine::standard();
    let findings = vec![finding_with(Severity::Blocker, 1.0)];

    let report = engine.score(&findings);

    assert_eq!(report.score, 90);
    assert_eq!(report.deductions.len(), 1);
    assert_eq!(report.deductions[0].points, 10);
    assert_eq!(report.deductions[0].finding_count, 1);
    matches_severity(report.deductions[0].source, Severity::Blocker);
}

#[test]
fn one_blocker_half_confidence_scores_95() {
    let engine = ScoreEngine::standard();
    let findings = vec![finding_with(Severity::Blocker, 0.5)];

    let report = engine.score(&findings);

    // 10 * 0.5 = 5.0 → ceil = 5 → 100 - 5 = 95
    assert_eq!(report.score, 95);
    assert_eq!(report.deductions.len(), 1);
    assert_eq!(report.deductions[0].points, 5);
}

#[test]
fn ten_blockers_certain_caps_at_60() {
    let engine = ScoreEngine::standard();
    // Spread across 10 distinct categories so the category-overweight
    // bonus (threshold = 5) does not also fire — this test isolates
    // the per-severity cap.
    let cats = [
        Category::Shape,
        Category::Slop,
        Category::Perf,
        Category::Bug,
        Category::Taint,
        Category::Concurrent,
        Category::Memory,
        Category::Deps,
        Category::Test,
        Category::Api,
    ];
    let findings: Vec<_> = cats
        .iter()
        .map(|c| finding_with_category(Severity::Blocker, 1.0, *c))
        .collect();

    let report = engine.score(&findings);

    // 10 * 10 = 100 → capped at blocker_cap = 60 → 100 - 60 = 40
    assert_eq!(report.score, 40);
    // One BySeverity deduction, no ByCategory deductions (max 1/category).
    assert_eq!(report.deductions.len(), 1);
    assert_eq!(report.deductions[0].points, 60);
    assert_eq!(report.deductions[0].finding_count, 10);
}

#[test]
fn five_required_plus_five_nits_scores_85() {
    let engine = ScoreEngine::standard();
    // Distinct categories per finding so category-overweight stays
    // silent (threshold = 5).
    let cats = [
        Category::Shape,
        Category::Slop,
        Category::Perf,
        Category::Bug,
        Category::Taint,
        Category::Concurrent,
        Category::Memory,
        Category::Deps,
        Category::Test,
        Category::Api,
    ];
    let mut findings = Vec::new();
    for c in cats.iter().take(5) {
        findings.push(finding_with_category(Severity::Required, 1.0, *c));
    }
    for c in cats.iter().skip(5).take(5) {
        findings.push(finding_with_category(Severity::Nit, 1.0, *c));
    }

    let report = engine.score(&findings);

    // 5 Required * 3 = 15; Nits free → 100 - 15 = 85
    assert_eq!(report.score, 85);
    assert_eq!(report.finding_counts.required, 5);
    assert_eq!(report.finding_counts.nit, 5);
    // Exactly one severity deduction (Required); Nits don't contribute.
    assert_eq!(report.deductions.len(), 1);
    matches_severity(report.deductions[0].source, Severity::Required);
}

#[test]
fn six_same_category_triggers_overweight() {
    let engine = ScoreEngine::standard();
    let findings: Vec<_> = (0..6)
        .map(|_| finding_with_category(Severity::Required, 1.0, Category::Slop))
        .collect();

    let report = engine.score(&findings);

    // Severity bucket: 6 * 3 = 18 (under cap of 30).
    // Category-overweight: 6 - 5 + 1 = 2 extra.
    // Total deduction: 18 + 2 = 20 → 80.
    assert_eq!(report.score, 80);
    let cat_deduction = report
        .deductions
        .iter()
        .find(|d| matches!(d.source, DeductionSource::ByCategory { .. }))
        .expect("category-overweight deduction emitted");
    assert_eq!(cat_deduction.points, 2);
    assert_eq!(cat_deduction.finding_count, 6);
}

#[test]
fn serialisation_is_deterministic() {
    let engine = ScoreEngine::standard();
    let findings = vec![
        finding_with_category(Severity::Blocker, 1.0, Category::Bug),
        finding_with_category(Severity::Required, 0.9, Category::Slop),
    ];

    let first = serde_json::to_string(&engine.score(&findings)).unwrap();
    let second = serde_json::to_string(&engine.score(&findings)).unwrap();
    assert_eq!(
        first, second,
        "two identical runs must serialise byte-for-byte"
    );

    expect![[r#"{"score":87,"deductions":[{"source":{"kind":"by_severity","severity":"blocker"},"points":10,"finding_count":1},{"source":{"kind":"by_severity","severity":"required"},"points":3,"finding_count":1}],"finding_counts":{"blocker":1,"required":1,"nit":0,"by_category":{"slop":1,"bug":1}}}"#]]
        .assert_eq(&first);
}

fn matches_severity(src: DeductionSource, expected: Severity) {
    match src {
        DeductionSource::BySeverity { severity } => assert_eq!(severity, expected),
        other => panic!("expected BySeverity({expected:?}), got {other:?}"),
    }
}
