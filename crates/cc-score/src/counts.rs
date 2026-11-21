//! Bucketed [`FindingCounts`] — reused by the engine and exposed
//! verbatim to consumers (CLI, ratchet diff, JSON dump).

use std::collections::BTreeMap;

use cc_finding::{Category, Finding, Severity};
use serde::{Deserialize, Serialize};

/// Bucket totals over a [`Finding`] slice.
///
/// `BTreeMap` (not `HashMap`) keeps `by_category` deterministic — two
/// runs over the same input emit byte-identical JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingCounts {
    /// Number of `Severity::Blocker` findings.
    pub blocker: u32,
    /// Number of `Severity::Required` findings.
    pub required: u32,
    /// Number of `Severity::Nit` findings.
    pub nit: u32,
    /// Per-category totals (ordered, deterministic).
    pub by_category: BTreeMap<Category, u32>,
}

impl FindingCounts {
    /// Bucket a slice of findings.
    ///
    /// Iteration is in slice order — the caller controls ordering;
    /// this routine never sorts.
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut counts = Self::default();
        for f in findings {
            counts.tally(f);
        }
        counts
    }

    fn tally(&mut self, f: &Finding) {
        match f.severity {
            Severity::Blocker => self.blocker = self.blocker.saturating_add(1),
            Severity::Required => self.required = self.required.saturating_add(1),
            Severity::Nit => self.nit = self.nit.saturating_add(1),
        }
        let entry = self.by_category.entry(f.category).or_insert(0);
        *entry = entry.saturating_add(1);
    }
}
