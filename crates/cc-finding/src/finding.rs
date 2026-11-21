//! The canonical [`Finding`] struct + [`FindingId`] (`UUIDv7`).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::category::Category;
use crate::cost::CostClaim;
use crate::evidence::Evidence;
use crate::fix::FixProposal;
use crate::location::{GitRef, Location, RelatedLocation};
use crate::message::ActionableMessage;
use crate::severity::{Confidence, Severity};
use crate::suppress::SuppressKey;
use crate::version::{KernelVersion, ProbeVersion};
use crate::StaticStr;

/// Sortable, machine-friendly identifier for a Finding.
///
/// Uses `UUIDv7` — the high bits encode a millisecond timestamp, so
/// natural ordering matches creation order and IDs sort lexicographically
/// on disk (handy for batch dumps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(pub Uuid);

impl FindingId {
    /// Generate a fresh `UUIDv7` id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for FindingId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The canonical Finding struct emitted by every Clean-Code-V12 probe.
///
/// The shape is locked: SARIF + `RDFormat` round-trips depend on every
/// field below. Schema-evolution requires bumping
/// [`crate::SCHEMA_VERSION`] and providing a migration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Unique, sortable id.
    pub id: FindingId,
    /// Stable rule slug, e.g. `"cc.shape.fn_length"`.
    pub rule_id: StaticStr,
    /// Top-level category.
    pub category: Category,
    /// Optional finer-grained subcategory (e.g. `"too_long"`).
    pub subcategory: Option<StaticStr>,

    /// Primary source range.
    pub location: Location,
    /// Secondary locations — dataflow steps, dup partners, etc.
    pub related: Vec<RelatedLocation>,

    /// Human-facing message.
    pub message: ActionableMessage,
    /// Evidence supporting the finding.
    pub evidence: Evidence,

    /// Severity level (intrinsic to the rule, not user-tunable).
    pub severity: Severity,
    /// Calibrated true-positive probability.
    pub confidence: Confidence,
    /// Cost claim — what fixing this is worth.
    pub cost: CostClaim,

    /// Optional machine-applicable repair.
    pub fix: Option<FixProposal>,
    /// Stable hash for baseline matching.
    pub suppress_key: SuppressKey,
    /// Git anchor for when this code was introduced.
    pub introduced_at: Option<GitRef>,
    /// Probe pack identity + kernel ABI window.
    pub probe_version: ProbeVersion,
    /// Kernel version that produced the finding.
    pub kernel_version: KernelVersion,
}

impl Finding {
    /// Combined cost × confidence ranking score.
    #[must_use]
    pub fn ranking_score(&self) -> f64 {
        self.cost.ranking_score() * f64::from(self.confidence.get())
    }
}
