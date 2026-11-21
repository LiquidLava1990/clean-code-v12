//! [`ScoreError`] — actionable error type for the score engine.
//!
//! Today the engine is total — every input slice produces a
//! [`crate::HealthScore`] without failure. The error type is reserved for
//! future work (custom-weights validation, calibration regressions). It
//! still ships with `R-ERR-ACTION` actionable messages so callers don't
//! pay a follow-up round-trip when they hit a future variant.

use thiserror::Error;

/// Errors produced by the score engine.
///
/// Every variant follows the **what + how** dogfood rule: the message
/// names what went wrong *and* what the caller should do.
#[derive(Debug, Error)]
pub enum ScoreError {
    /// A custom [`crate::Weights`] override violated an invariant
    /// (e.g. `min_score > 100`). The fix is to clamp the override into
    /// `[0, 100]` before passing it in.
    #[error(
        "invalid weights: {field} = {value} is outside [{min}, {max}]; \
         clamp the value before calling ScoreEngine::with_weights"
    )]
    InvalidWeights {
        /// Name of the offending [`crate::Weights`] field.
        field: &'static str,
        /// Out-of-range value supplied by the caller.
        value: u32,
        /// Inclusive minimum permitted.
        min: u32,
        /// Inclusive maximum permitted.
        max: u32,
    },
}
