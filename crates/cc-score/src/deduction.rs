//! [`Deduction`] line-items — what the engine subtracted from 100,
//! itemised so the CLI can render `-10 (1 Blocker)` etc.

use cc_finding::{Category, Severity};
use serde::{Deserialize, Serialize};

/// Where a [`Deduction`] came from.
///
/// The variant set is deliberately closed; new dimensions should be
/// added here (and to the engine) rather than smuggled through
/// `ByCategory` with a sentinel category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeductionSource {
    /// Severity-bucket deduction (Blocker / Required / Nit).
    BySeverity {
        /// The severity that produced this deduction.
        severity: Severity,
    },
    /// Category-overweight bonus deduction — fired when a single
    /// [`Category`] crosses [`crate::Weights::category_overweight_threshold`].
    ByCategory {
        /// The category that crossed the threshold.
        category: Category,
    },
    /// Reserved — emitted when a per-severity cap clipped the
    /// contribution. Currently only attached as metadata on
    /// `BySeverity` deductions; kept here for forward compatibility.
    Cap,
}

/// Single line-item subtracted from the perfect-100 baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deduction {
    /// Where the deduction came from.
    pub source: DeductionSource,
    /// Points subtracted (already saturated to `u8`).
    pub points: u8,
    /// Number of findings that contributed.
    pub finding_count: u32,
}

impl Deduction {
    /// Construct a severity-bucket deduction.
    #[must_use]
    pub const fn severity(sev: Severity, points: u8, finding_count: u32) -> Self {
        Self {
            source: DeductionSource::BySeverity { severity: sev },
            points,
            finding_count,
        }
    }

    /// Construct a category-overweight deduction.
    #[must_use]
    pub const fn category(cat: Category, points: u8, finding_count: u32) -> Self {
        Self {
            source: DeductionSource::ByCategory { category: cat },
            points,
            finding_count,
        }
    }
}
