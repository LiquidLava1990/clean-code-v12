//! Repo-wide error-class taxonomy.
//!
//! Counts distinct error / exception class names observed in `Try` handlers
//! and `Return` nodes annotated as raises. Downstream rules use the resulting
//! [`ErrorPatternMap`] to flag uses of unknown error classes (likely typos)
//! and to surface the canonical error vocabulary of a repo.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Map of error/exception class name → number of times it was observed
/// being raised or caught across the repo.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorPatternMap {
    counts: BTreeMap<String, u64>,
}

impl ErrorPatternMap {
    /// Empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one observation of `class_name`.
    pub fn record(&mut self, class_name: impl Into<String>) {
        let key = class_name.into();
        if key.is_empty() {
            return;
        }
        *self.counts.entry(key).or_insert(0) += 1;
    }

    /// Lookup count for `class_name`, defaulting to 0.
    #[must_use]
    pub fn count(&self, class_name: &str) -> u64 {
        self.counts.get(class_name).copied().unwrap_or(0)
    }

    /// Iterate over all known error class names (no count, name-only).
    pub fn known(&self) -> impl Iterator<Item = &str> {
        self.counts.keys().map(String::as_str)
    }

    /// Total error class names observed (cardinality, not sum-of-counts).
    #[must_use]
    pub fn distinct(&self) -> usize {
        self.counts.len()
    }

    /// Total raise/catch observations across all classes.
    #[must_use]
    pub fn total_observations(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Borrow the raw count map.
    #[must_use]
    pub const fn raw(&self) -> &BTreeMap<String, u64> {
        &self.counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_count() {
        let mut m = ErrorPatternMap::new();
        m.record("ValueError");
        m.record("ValueError");
        m.record("RuntimeError");
        assert_eq!(m.count("ValueError"), 2);
        assert_eq!(m.count("RuntimeError"), 1);
        assert_eq!(m.count("KeyError"), 0);
        assert_eq!(m.distinct(), 2);
        assert_eq!(m.total_observations(), 3);
    }

    #[test]
    fn known_iter() {
        let mut m = ErrorPatternMap::new();
        m.record("A");
        m.record("B");
        let known: std::collections::HashSet<&str> = m.known().collect();
        assert!(known.contains("A"));
        assert!(known.contains("B"));
        assert_eq!(known.len(), 2);
    }

    #[test]
    fn empty_class_is_ignored() {
        let mut m = ErrorPatternMap::new();
        m.record("");
        assert_eq!(m.distinct(), 0);
    }
}
