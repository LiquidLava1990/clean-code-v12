//! Tunable scoring constants — per-severity weights, caps, thresholds.
//!
//! The defaults match the spec on disk
//! (`crates/cc-score/SPEC.md` → "Algorithm"). Custom [`Weights`] are
//! permitted via [`crate::ScoreEngine::with_weights`] so tests can
//! exercise edge cases without polluting production behaviour.

use serde::{Deserialize, Serialize};

/// Tunable weights driving [`crate::ScoreEngine::score`].
///
/// All fields are public so tests can mutate individual knobs; the
/// production wiring should always go through [`Weights::default`] /
/// [`Weights::standard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Weights {
    /// Points deducted per `Blocker` (before confidence weighting). Default `10`.
    pub blocker_each: u8,
    /// Points deducted per `Required` (before confidence weighting). Default `3`.
    pub required_each: u8,
    /// Points deducted per `Nit` — default `0` (Nits are surfaced but
    /// don't deduct).
    pub nit_each: u8,
    /// Maximum total contribution from `Blocker` findings. Default `60`.
    pub blocker_cap: u8,
    /// Maximum total contribution from `Required` findings. Default `30`.
    pub required_cap: u8,
    /// Threshold at which a single category starts incurring an extra
    /// deduction. Default `5` — five+ findings in the same category
    /// signal "your repo has a systemic axis problem, not a one-off."
    pub category_overweight_threshold: u32,
    /// Score floor — the engine never reports below this. Default `0`.
    pub min_score: u8,
}

impl Weights {
    /// Construct the canonical production weights. Equivalent to
    /// [`Weights::default`] but spelled out for callers that want to
    /// communicate "I deliberately picked the standard set."
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            blocker_each: 10,
            required_each: 3,
            nit_each: 0,
            blocker_cap: 60,
            required_cap: 30,
            category_overweight_threshold: 5,
            min_score: 0,
        }
    }
}

impl Default for Weights {
    fn default() -> Self {
        Self::standard()
    }
}
