//! Baseline diff — partition a finding stream against a [`BaselineRepo`].

use std::collections::HashSet;

use cc_finding::{Finding, SuppressKey};

use crate::repo::BaselineRepo;

/// Partitioned outcome of [`apply`].
#[derive(Debug, Clone, Default)]
pub struct DiffOutcome {
    /// Findings whose `suppress_key` is NOT in the baseline — these
    /// escalate to the caller's primary sink.
    pub new: Vec<Finding>,
    /// Findings whose `suppress_key` IS in the baseline — silenced,
    /// but their entries get touched so they don't drift into prune.
    pub persisted: Vec<Finding>,
    /// Baseline keys that the current run did NOT re-observe — prune
    /// candidates (the caller decides whether to drop them).
    pub escaped: Vec<SuppressKey>,
}

impl DiffOutcome {
    /// `true` iff there are no new findings to escalate.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.new.is_empty()
    }
}

/// Diff `findings` against `baseline`, mutating the baseline so each
/// persisted entry is touched.
///
/// Behaviour:
/// 1. Each finding is partitioned into `new` (key absent) or
///    `persisted` (key present + entry touched).
/// 2. Any baseline key that did NOT show up in `findings` is reported
///    as `escaped` (prune candidate). The baseline is NOT auto-pruned —
///    the caller invokes [`BaselineRepo::prune_unseen_since`] explicitly
///    once their cool-down policy is satisfied.
pub fn apply(baseline: &mut BaselineRepo, findings: &[Finding]) -> DiffOutcome {
    let mut outcome = DiffOutcome::default();
    let mut seen: HashSet<SuppressKey> = HashSet::with_capacity(findings.len());

    for f in findings {
        partition_one(baseline, f, &mut outcome, &mut seen);
    }

    outcome.escaped = collect_escaped(baseline, &seen);
    outcome
}

fn partition_one(
    baseline: &mut BaselineRepo,
    finding: &Finding,
    outcome: &mut DiffOutcome,
    seen: &mut HashSet<SuppressKey>,
) {
    let key = finding.suppress_key;
    seen.insert(key);
    if baseline.contains(&key) {
        baseline.touch(&key);
        outcome.persisted.push(finding.clone());
    } else {
        outcome.new.push(finding.clone());
    }
}

fn collect_escaped(baseline: &BaselineRepo, seen: &HashSet<SuppressKey>) -> Vec<SuppressKey> {
    baseline
        .baseline()
        .entries
        .keys()
        .filter(|k| !seen.contains(*k))
        .copied()
        .collect()
}
