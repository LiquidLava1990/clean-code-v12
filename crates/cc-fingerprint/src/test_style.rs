//! Test-file style heuristic.
//!
//! Recognises functions that are clearly tests (`test_*` / `*Test` / live
//! under `tests/`) and counts the assertion-style calls inside them. The
//! resulting profile lets downstream rules flag tests that drift from the
//! repo's dominant assertion vocabulary.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Aggregate test-style observations across the repo.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestStyleProfile {
    /// Number of recognised test functions.
    pub test_function_count: u64,
    /// `assert_call_name` -> times observed.
    pub assertion_counts: BTreeMap<String, u64>,
}

impl TestStyleProfile {
    /// Empty profile.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one recognised test function.
    pub fn record_test_fn(&mut self) {
        self.test_function_count += 1;
    }

    /// Record one assertion-style call observed inside a recognised test.
    pub fn record_assertion(&mut self, call_name: impl Into<String>) {
        let key = call_name.into();
        if key.is_empty() {
            return;
        }
        *self.assertion_counts.entry(key).or_insert(0) += 1;
    }

    /// Dominant assertion call name, if a clear plurality (>50%) exists and
    /// at least 5 assertions have been observed.
    #[must_use]
    pub fn dominant_assertion(&self) -> Option<&str> {
        let total: u64 = self.assertion_counts.values().sum();
        if total < 5 {
            return None;
        }
        let (name, count) = self
            .assertion_counts
            .iter()
            .max_by_key(|(_, count)| *count)?;
        #[allow(clippy::cast_precision_loss)] // share is a heuristic; counts << 2^52
        let share = *count as f64 / total as f64;
        if share >= 0.5 {
            Some(name.as_str())
        } else {
            None
        }
    }
}

/// Heuristic: is the given function name + path a test?
#[must_use]
pub fn is_test_function(name: &str, file_path: Option<&str>) -> bool {
    if name.starts_with("test_") {
        return true;
    }
    if name.ends_with("Test") || name.ends_with("Tests") {
        return true;
    }
    if let Some(path) = file_path {
        let lowered = path.replace('\\', "/").to_ascii_lowercase();
        if lowered.contains("/tests/")
            || lowered.starts_with("tests/")
            || lowered.contains("_test.")
            || lowered.ends_with("_test.py")
            || lowered.ends_with(".test.ts")
            || lowered.ends_with(".test.tsx")
            || lowered.ends_with(".spec.ts")
        {
            return true;
        }
    }
    false
}

/// Heuristic: is `call_name` an assertion-style call we should track?
#[must_use]
pub fn is_assertion_call(call_name: &str) -> bool {
    if call_name == "assert" {
        return true;
    }
    if call_name.starts_with("assert_") || call_name.starts_with("assertEq") {
        return true;
    }
    matches!(
        call_name,
        "expect" | "should" | "assertEqual" | "assertTrue" | "assertFalse"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_test_by_name() {
        assert!(is_test_function("test_foo", None));
        assert!(is_test_function("MyClassTest", None));
        assert!(is_test_function("RouterTests", None));
        assert!(!is_test_function("regular_fn", None));
    }

    #[test]
    fn detects_test_by_path() {
        assert!(is_test_function(
            "foo",
            Some("crates/x/tests/integration.rs")
        ));
        assert!(is_test_function("foo", Some("tests\\unit_test.py")));
        assert!(is_test_function("foo", Some("src/foo_test.go")));
        assert!(is_test_function("foo", Some("src/foo.test.ts")));
        assert!(!is_test_function("foo", Some("src/foo.rs")));
    }

    #[test]
    fn assertion_classification() {
        assert!(is_assertion_call("assert"));
        assert!(is_assertion_call("assert_eq"));
        assert!(is_assertion_call("assertEqual"));
        assert!(is_assertion_call("expect"));
        assert!(!is_assertion_call("println"));
    }

    #[test]
    fn dominant_assertion_threshold() {
        let mut p = TestStyleProfile::new();
        for _ in 0..4 {
            p.record_assertion("assert_eq");
        }
        assert_eq!(p.dominant_assertion(), None, "below sample floor");
        p.record_assertion("assert_eq");
        assert_eq!(p.dominant_assertion(), Some("assert_eq"));

        for _ in 0..10 {
            p.record_assertion("expect");
        }
        // expect 10 vs assert_eq 5 → 10/15 ≈ 66% dominant.
        assert_eq!(p.dominant_assertion(), Some("expect"));
    }
}
