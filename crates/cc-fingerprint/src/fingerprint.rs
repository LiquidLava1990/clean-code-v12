//! The finalized [`Fingerprint`] struct returned by
//! [`crate::FingerprintBuilder::finalize`].

use cc_cpg::NodeKind;
use serde::{Deserialize, Serialize};

use crate::errors::ErrorPatternMap;
use crate::imports::LayerGraph;
use crate::naming::{NamingDistribution, NamingStyle};
use crate::test_style::TestStyleProfile;

/// Sample-size summary — useful for downstream rules that scale their
/// confidence to the size of the cohort.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleSize {
    /// Number of files / batches contributed.
    pub files: u32,
    /// Total identifiers (across all kinds) recorded into the naming
    /// distribution.
    pub identifiers: u64,
}

/// A finalized per-repo style fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Per-`NodeKind` naming distribution.
    pub naming: NamingDistribution,
    /// Repo-wide error class taxonomy.
    pub errors: ErrorPatternMap,
    /// Observed module-to-module import graph.
    pub layering: LayerGraph,
    /// Test-file style profile.
    pub test_style: TestStyleProfile,
    /// Sample-size headline numbers.
    pub sample_size: SampleSize,
}

impl Fingerprint {
    /// Empty fingerprint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Dominant naming style for `kind`, if any (≥80% over ≥10 samples).
    #[must_use]
    pub fn dominant_naming(&self, kind: NodeKind) -> Option<NamingStyle> {
        self.naming.dominant(kind)
    }

    /// Convenience: `name` is an outlier under `kind`.
    #[must_use]
    pub fn is_naming_outlier(&self, kind: NodeKind, name: &str) -> bool {
        self.naming.is_outlier(kind, name)
    }

    /// All known error class names (canonical taxonomy of the repo).
    pub fn known_errors(&self) -> impl Iterator<Item = &str> {
        self.errors.known()
    }
}
