//! Severity + Confidence — the two intrinsic ranking dimensions of a Finding.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::FindingError;

/// Three-level severity classification matching the code-review labels.
///
/// Severity is **not** user-tunable. It is a property of the rule.
/// What is tunable is suppression (per-finding) and probe-pack inclusion
/// (per-repo, per-family — except Family 0 which is forced).
///
/// # Ordering
///
/// `Blocker > Required > Nit`. The derived [`Ord`] uses the variant
/// declaration order, so do **not** reorder the variants without
/// updating the ordering tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Optional fix — never blocks merges. Maps to SARIF `note`.
    Nit,
    /// Must fix before session close. Maps to SARIF `warning`.
    Required,
    /// Merge refused. Tier-0 violations, taint hits, CVE-reachable.
    /// Maps to SARIF `error`.
    Blocker,
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl Severity {
    /// Numeric rank, higher = more severe. Used for [`Ord`].
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Nit => 0,
            Self::Required => 1,
            Self::Blocker => 2,
        }
    }

    /// SARIF 2.1.0 `result.level` mapping.
    #[must_use]
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Self::Blocker => "error",
            Self::Required => "warning",
            Self::Nit => "note",
        }
    }

    /// Lower-case canonical name (used for parsing + display).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocker => "blocker",
            Self::Required => "required",
            Self::Nit => "nit",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = FindingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "blocker" | "error" => Ok(Self::Blocker),
            "required" | "warning" => Ok(Self::Required),
            "nit" | "note" | "info" => Ok(Self::Nit),
            _ => Err(FindingError::UnknownSeverity {
                input: s.to_owned(),
            }),
        }
    }
}

/// Calibrated probability that a finding is a true positive.
///
/// Always lies in `[0.0, 1.0]`. Values outside this range are clamped
/// silently by [`Confidence::new`]. Probe authors must calibrate against
/// the labeled corpus in `tests/calibration.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidence(pub f32);

impl Confidence {
    /// Construct a confidence, clamping to `[0.0, 1.0]`.
    ///
    /// `NaN` collapses to `0.0` because an uncalibrated probe should
    /// never receive the benefit of the doubt.
    #[must_use]
    pub const fn new(value: f32) -> Self {
        if value.is_nan() || value < 0.0 {
            Self(0.0)
        } else if value > 1.0 {
            Self(1.0)
        } else {
            Self(value)
        }
    }

    /// Convenience constructor for a fully calibrated, high-confidence
    /// finding.
    #[must_use]
    pub const fn certain() -> Self {
        Self(1.0)
    }

    /// Inner f32 value.
    #[must_use]
    pub const fn get(self) -> f32 {
        self.0
    }

    /// Default emission threshold for the given [`Severity`].
    ///
    /// Findings whose confidence falls below this threshold are dropped
    /// before reaching any sink.
    #[must_use]
    pub const fn threshold_for(sev: Severity) -> f32 {
        match sev {
            Severity::Blocker => 0.98,
            Severity::Required => 0.85,
            Severity::Nit => 0.60,
        }
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Blocker > Severity::Required);
        assert!(Severity::Required > Severity::Nit);
        assert!(Severity::Blocker > Severity::Nit);
    }

    #[test]
    fn confidence_clamps() {
        assert!((Confidence::new(1.5).get() - 1.0).abs() < f32::EPSILON);
        assert!((Confidence::new(-0.5).get() - 0.0).abs() < f32::EPSILON);
        assert!((Confidence::new(0.42).get() - 0.42).abs() < f32::EPSILON);
    }

    #[test]
    fn confidence_nan_collapses_to_zero() {
        assert!(Confidence::new(f32::NAN).get() == 0.0);
    }

    #[test]
    fn severity_display_roundtrip() {
        for sev in [Severity::Blocker, Severity::Required, Severity::Nit] {
            let s = sev.to_string();
            let parsed: Severity = s.parse().unwrap();
            assert_eq!(parsed, sev);
        }
    }

    #[test]
    fn severity_parse_aliases() {
        assert_eq!("error".parse::<Severity>().unwrap(), Severity::Blocker);
        assert_eq!("warning".parse::<Severity>().unwrap(), Severity::Required);
        assert_eq!("note".parse::<Severity>().unwrap(), Severity::Nit);
    }

    #[test]
    fn severity_parse_unknown_is_actionable() {
        let err = "totally-fake".parse::<Severity>().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("blocker"));
        assert!(msg.contains("required"));
        assert!(msg.contains("nit"));
    }
}
