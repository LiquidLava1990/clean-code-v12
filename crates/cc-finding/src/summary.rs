//! Aggregate counters returned by [`FindingSink::finish`].
//!
//! [`FindingSink::finish`]: crate::FindingSink::finish

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::category::Category;
use crate::finding::Finding;
use crate::severity::Severity;

/// Aggregate counters for a sink run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// Total number of findings emitted.
    pub total: u32,
    /// Counts by severity.
    pub by_severity: BTreeMap<Severity, u32>,
    /// Counts by category.
    pub by_category: BTreeMap<Category, u32>,
}

impl Summary {
    /// Create an empty summary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Account for a single finding.
    pub fn record(&mut self, f: &Finding) {
        self.total = self.total.saturating_add(1);
        *self.by_severity.entry(f.severity).or_insert(0) += 1;
        *self.by_category.entry(f.category).or_insert(0) += 1;
    }

    /// True iff at least one [`Severity::Blocker`] finding was recorded.
    #[must_use]
    pub fn has_blocker(&self) -> bool {
        self.by_severity
            .get(&Severity::Blocker)
            .copied()
            .unwrap_or(0)
            > 0
    }
}
