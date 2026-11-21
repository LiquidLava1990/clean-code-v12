//! Clean Code V12 — deterministic health score over a [`cc_finding::Finding`] stream.
//!
//! The kernel runs every probe pack against a repo, drains a stream of
//! [`cc_finding::Finding`]s, and asks this crate: *"what is the repo's
//! health right now, on a 0..=100 scale?"*. The number is what
//! `cc check` prints at the end of a run (`Health 87/100`) and what the
//! ratchet uses to gate pull requests — a regression blocks the merge.
//!
//! # Design tenets
//!
//! 1. **Deterministic.** Identical input slice → byte-identical
//!    [`HealthScore`] (and byte-identical serde JSON dump). No
//!    `HashMap`, no system clock, no float ordering surprises.
//! 2. **Confidence-weighted.** A 0.5-confidence finding contributes
//!    half a point — calibration matters, and probe authors who lie
//!    about confidence either over-deduct (and get pushed back on) or
//!    under-deduct (and get out-ratcheted). Either way the system
//!    self-corrects.
//! 3. **Capped per dimension.** A drive-by PR that introduces 100
//!    `Blocker`s should *not* drag the score to -INF; it should hit
//!    the per-dimension cap (default 60). The cap exists so a single
//!    rogue probe can't dominate the score.
//! 4. **Ratchet-friendly.** [`HealthScore`] is `Serialize`-able to
//!    `.cc/score.json`; the ratchet diff just reads two JSON files and
//!    refuses regressions.
//!
//! # File map
//!
//! | Module        | Purpose                                  |
//! |---------------|------------------------------------------|
//! | [`error`]     | [`ScoreError`] — actionable error type   |
//! | [`weights`]   | [`Weights`] — tunable scoring constants  |
//! | [`counts`]    | [`FindingCounts`] — bucketed totals      |
//! | [`deduction`] | [`Deduction`] / [`DeductionSource`]      |
//! | [`engine`]    | [`ScoreEngine`] + [`HealthScore`]        |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod counts;
pub mod deduction;
pub mod engine;
pub mod error;
pub mod weights;

pub use counts::FindingCounts;
pub use deduction::{Deduction, DeductionSource};
pub use engine::{HealthScore, ScoreEngine};
pub use error::ScoreError;
pub use weights::Weights;
