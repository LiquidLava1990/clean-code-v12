//! Integration tests for `cc-test-fixtures`.

use std::collections::HashSet;

use camino::Utf8PathBuf;
use cc_test_fixtures::{write_to_tempdir, FixtureCatalog, FixtureKind, Language};

#[test]
fn catalog_meets_minimum_size() {
    let total = FixtureCatalog::all().len();
    assert!(
        total >= 40,
        "expected >= 40 fixtures across the corpus, found {total}"
    );
}

#[test]
fn every_language_has_at_least_ten_fixtures() {
    for lang in [
        Language::Python,
        Language::Typescript,
        Language::Go,
        Language::Rust,
    ] {
        let count = FixtureCatalog::by_language(lang).count();
        assert!(
            count >= 10,
            "expected >= 10 fixtures for {lang:?}, found {count}"
        );
    }
}

#[test]
fn every_fixture_has_non_empty_source_bytes() {
    for fixture in FixtureCatalog::all() {
        assert!(
            !fixture.source.is_empty(),
            "fixture {} has empty source bytes",
            fixture.relative_path,
        );
    }
}

#[test]
fn relative_path_matches_language_dir() {
    for fixture in FixtureCatalog::all() {
        let expected_prefix = format!("{}/", fixture.language.dir_name());
        assert!(
            fixture.relative_path.starts_with(&expected_prefix),
            "fixture {} does not start with {}",
            fixture.relative_path,
            expected_prefix,
        );
    }
}

#[test]
fn relative_paths_are_unique() {
    let mut seen: HashSet<&str> = HashSet::new();
    for fixture in FixtureCatalog::all() {
        assert!(
            seen.insert(fixture.relative_path),
            "duplicate relative_path: {}",
            fixture.relative_path,
        );
    }
}

#[test]
fn lookup_python_fn_length_violating_returns_some() {
    let fixture = FixtureCatalog::lookup(
        Language::Python,
        "cc.shape.fn_length",
        FixtureKind::Violating,
    )
    .expect("python fn_length violating must exist");
    assert_eq!(fixture.language, Language::Python);
    assert_eq!(fixture.rule_id, "cc.shape.fn_length");
    assert_eq!(fixture.kind, FixtureKind::Violating);
    assert!(std::path::Path::new(fixture.relative_path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("py")));
}

#[test]
fn lookup_returns_none_for_rust_inheritance_gap() {
    // Rust has no class inheritance — no fixture should exist.
    let result = FixtureCatalog::lookup(
        Language::Rust,
        "cc.shape.no_inheritance",
        FixtureKind::Violating,
    );
    assert!(result.is_none(), "rust no_inheritance gap must remain");
}

#[test]
fn by_rule_groups_correctly() {
    let fn_length: Vec<_> = FixtureCatalog::by_rule("cc.shape.fn_length").collect();
    assert_eq!(
        fn_length.len(),
        8,
        "fn_length rule should have 4 langs x 2 kinds = 8 fixtures, got {}",
        fn_length.len(),
    );
}

#[test]
fn for_rule_kind_filters_by_both_axes() {
    let violating: Vec<_> =
        FixtureCatalog::for_rule_kind("cc.shape.fn_length", FixtureKind::Violating).collect();
    assert_eq!(violating.len(), 4, "one violating fixture per language");
    for fixture in violating {
        assert_eq!(fixture.kind, FixtureKind::Violating);
        assert_eq!(fixture.rule_id, "cc.shape.fn_length");
    }
}

#[test]
fn write_to_tempdir_round_trips_bytes() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let root =
        Utf8PathBuf::from_path_buf(tempdir.path().to_path_buf()).expect("tempdir path is utf-8");

    let fixtures: Vec<_> = FixtureCatalog::all().iter().collect();
    write_to_tempdir(&fixtures, &root).expect("materialise fixtures");

    for fixture in FixtureCatalog::all() {
        let mut on_disk = root.clone();
        for segment in fixture.relative_path.split('/') {
            on_disk.push(segment);
        }
        let bytes = std::fs::read(&on_disk)
            .unwrap_or_else(|err| panic!("failed to read materialised fixture {on_disk}: {err}"));
        assert_eq!(
            bytes.as_slice(),
            fixture.source,
            "materialised bytes diverged from embedded source for {}",
            fixture.relative_path,
        );
    }
}
