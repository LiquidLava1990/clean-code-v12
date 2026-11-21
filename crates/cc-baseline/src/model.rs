//! On-disk baseline data model — [`Baseline`] + [`BaselineEntry`].
//!
//! These types are pure data plus serde derives. All mutation happens in
//! [`crate::repo::BaselineRepo`]; this module is the wire format.

use std::collections::BTreeMap;

use cc_finding::SuppressKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Highest [`Baseline::schema_version`] this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// One entry per accepted finding, keyed by [`SuppressKey`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Stable rule slug, e.g. `"cc.shape.fn_length"`.
    pub rule_id: String,
    /// First time this finding was accepted into the baseline.
    pub accepted_at: DateTime<Utc>,
    /// Git author / human reviewer who accepted it (best-effort).
    pub accepted_by: Option<String>,
    /// Free-form note ("legacy code, fix in M2").
    pub reason: Option<String>,
    /// Most recent run that re-saw the finding — used for prune.
    pub last_seen_at: DateTime<Utc>,
    /// Number of runs that re-saw the finding (incl. acceptance).
    pub seen_count: u32,
}

impl BaselineEntry {
    /// Construct a fresh entry from a [`cc_finding::Finding`] reference.
    #[must_use]
    pub fn from_finding(
        finding: &cc_finding::Finding,
        reason: Option<String>,
        who: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            rule_id: finding.rule_id.as_ref().to_owned(),
            accepted_at: now,
            accepted_by: who,
            reason,
            last_seen_at: now,
            seen_count: 1,
        }
    }

    /// Bump `last_seen_at` to now and increment `seen_count`.
    pub fn touch(&mut self) {
        self.last_seen_at = Utc::now();
        self.seen_count = self.seen_count.saturating_add(1);
    }
}

/// On-disk baseline — a snapshot of accepted findings keyed by their
/// stable [`SuppressKey`].
///
/// Entries are stored in a [`BTreeMap`] so the JSON output is
/// deterministically ordered (handy for review diffs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// On-disk schema version. Bump on non-additive change.
    pub schema_version: u32,
    /// When the baseline was first generated.
    pub created_at: DateTime<Utc>,
    /// Git commit SHA the baseline was generated against (if known).
    pub git_ref: Option<String>,
    /// Kernel version that produced the baseline (for migration hints).
    pub kernel_version: String,
    /// Accepted findings keyed by [`SuppressKey`].
    pub entries: BTreeMap<SuppressKey, BaselineEntry>,
}

impl Baseline {
    /// Construct an empty baseline at the current schema + kernel version.
    #[must_use]
    pub fn empty(git_ref: Option<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            created_at: Utc::now(),
            git_ref,
            kernel_version: kernel_version_string(),
            entries: BTreeMap::new(),
        }
    }
}

impl Default for Baseline {
    fn default() -> Self {
        Self::empty(None)
    }
}

/// Stable kernel-version string the baseline records.
///
/// We pin this to the `cc-finding` schema version + the cargo package
/// version of `cc-baseline` so old baselines self-identify when the
/// kernel walks forward.
#[must_use]
pub fn kernel_version_string() -> String {
    format!(
        "cc-baseline {} / finding-schema {}",
        env!("CARGO_PKG_VERSION"),
        cc_finding::SCHEMA_VERSION
    )
}
