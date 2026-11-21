//! [`ScoreEngine`] — pure, deterministic [`Finding`] → [`HealthScore`]
//! reducer.
//!
//! The whole pipeline is a 4-step fold:
//!
//! 1. Bucket findings into [`FindingCounts`].
//! 2. Compute confidence-weighted, capped severity deductions.
//! 3. Compute category-overweight bonus deductions.
//! 4. Saturate to `[min_score, 100]`.
//!
//! Every step is allocation-light, branch-light, and side-effect-free
//! — repeated runs on the same input return byte-identical output.

use cc_finding::{Category, Confidence, Finding, Severity};
use serde::{Deserialize, Serialize};

use crate::counts::FindingCounts;
use crate::deduction::Deduction;
use crate::weights::Weights;

/// Outcome of [`ScoreEngine::score`] — what `ccv12 check` prints and what
/// the ratchet writes to `.cc/score.json`.
///
/// Implements [`Serialize`] / [`Deserialize`] with deterministic field
/// ordering (struct order = serde output order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthScore {
    /// Final score, clamped to `[Weights::min_score, 100]`.
    pub score: u8,
    /// Itemised deductions in stable order:
    /// severity buckets first (Blocker → Required → Nit), then
    /// category-overweight in `Category` order.
    pub deductions: Vec<Deduction>,
    /// Bucketed totals fed into the engine.
    pub finding_counts: FindingCounts,
}

/// Pure, deterministic finding-stream → health-score reducer.
#[derive(Debug, Clone, Copy)]
pub struct ScoreEngine {
    weights: Weights,
}

impl ScoreEngine {
    /// Engine with the canonical production [`Weights`].
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            weights: Weights::standard(),
        }
    }

    /// Engine with custom [`Weights`] — useful for tests + experiments.
    #[must_use]
    pub const fn with_weights(weights: Weights) -> Self {
        Self { weights }
    }

    /// Compute over a finding slice — pure, deterministic.
    #[must_use]
    pub fn score(&self, findings: &[Finding]) -> HealthScore {
        let counts = FindingCounts::from_findings(findings);
        let mut deductions = Vec::new();
        let mut total: u32 = 0;

        total = total.saturating_add(self.push_severity_deduction(
            findings,
            Severity::Blocker,
            counts.blocker,
            &mut deductions,
        ));
        total = total.saturating_add(self.push_severity_deduction(
            findings,
            Severity::Required,
            counts.required,
            &mut deductions,
        ));
        total = total.saturating_add(self.push_severity_deduction(
            findings,
            Severity::Nit,
            counts.nit,
            &mut deductions,
        ));

        total = total
            .saturating_add(self.push_category_deductions(&counts.by_category, &mut deductions));

        let score = self.clamp_score(total);
        HealthScore {
            score,
            deductions,
            finding_counts: counts,
        }
    }

    /// Append (and return points for) a single severity bucket.
    /// Returns `0` when the bucket is empty or the per-severity weight
    /// is `0` (e.g. `Nit` by default).
    fn push_severity_deduction(
        &self,
        findings: &[Finding],
        sev: Severity,
        count: u32,
        out: &mut Vec<Deduction>,
    ) -> u32 {
        if count == 0 {
            return 0;
        }
        let weight = self.severity_weight(sev);
        if weight == 0 {
            return 0;
        }
        let cap = self.severity_cap(sev);
        let weighted = weighted_count_for(findings, sev);
        let raw = (weighted * f32::from(weight)).ceil();
        let raw_u32 = clamp_to_u32(raw);
        let points = raw_u32.min(u32::from(cap));
        if points == 0 {
            return 0;
        }
        out.push(Deduction::severity(sev, saturate_u8(points), count));
        points
    }

    /// Append category-overweight bonus deductions and return their
    /// summed contribution.
    fn push_category_deductions(
        &self,
        by_category: &std::collections::BTreeMap<Category, u32>,
        out: &mut Vec<Deduction>,
    ) -> u32 {
        let threshold = self.weights.category_overweight_threshold;
        if threshold == 0 {
            return 0;
        }
        let mut sum: u32 = 0;
        for (cat, n) in by_category {
            if *n < threshold {
                continue;
            }
            let extra = n.saturating_sub(threshold).saturating_add(1);
            out.push(Deduction::category(*cat, saturate_u8(extra), *n));
            sum = sum.saturating_add(extra);
        }
        sum
    }

    const fn severity_weight(&self, sev: Severity) -> u8 {
        match sev {
            Severity::Blocker => self.weights.blocker_each,
            Severity::Required => self.weights.required_each,
            Severity::Nit => self.weights.nit_each,
        }
    }

    const fn severity_cap(&self, sev: Severity) -> u8 {
        match sev {
            Severity::Blocker => self.weights.blocker_cap,
            Severity::Required => self.weights.required_cap,
            // Nits aren't capped today (they don't deduct); reuse u8::MAX
            // so a future non-zero `nit_each` doesn't silently get clipped.
            Severity::Nit => u8::MAX,
        }
    }

    fn clamp_score(&self, total_deduction: u32) -> u8 {
        let after = 100u32.saturating_sub(total_deduction);
        let after_u8 = saturate_u8(after);
        after_u8.max(self.weights.min_score)
    }
}

impl Default for ScoreEngine {
    fn default() -> Self {
        Self::standard()
    }
}

/// Sum the confidence values of every finding in `findings` whose
/// severity matches `sev`. The returned float is *not* clamped — the
/// engine clamps after multiplying by the weight.
fn weighted_count_for(findings: &[Finding], sev: Severity) -> f32 {
    findings
        .iter()
        .filter(|f| f.severity == sev)
        .map(|f| Confidence::get(f.confidence))
        .sum::<f32>()
}

/// Saturating cast `u32 → u8` — caps at `u8::MAX` instead of wrapping.
const fn saturate_u8(v: u32) -> u8 {
    if v > u8::MAX as u32 {
        u8::MAX
    } else {
        // Truncation is impossible here — guarded by the branch above.
        #[allow(clippy::cast_possible_truncation)]
        let narrowed = v as u8;
        narrowed
    }
}

/// Saturating cast `f32 → u32` — handles `NaN`, negatives, and overflow.
///
/// We deliberately accept the precision loss in the `>=` comparison
/// against `u32::MAX as f32`: any `f32` large enough for that branch
/// already exceeds `u32::MAX`, so the imprecise threshold can only
/// over-clamp (which is the safe direction).
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn clamp_to_u32(v: f32) -> u32 {
    if v.is_nan() || v <= 0.0 {
        0
    } else if v >= u32::MAX as f32 {
        u32::MAX
    } else {
        v as u32
    }
}
