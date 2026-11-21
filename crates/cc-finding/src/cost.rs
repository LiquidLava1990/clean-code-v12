//! Cost claims — what fixing this finding is worth.

use serde::{Deserialize, Serialize};

use crate::StaticStr;

const fn clamp_unit(v: f32) -> f32 {
    // `is_nan` and the comparison branches must be expressed
    // separately because `f32::clamp` is not const.
    if v.is_nan() || v < 0.0 {
        0.0
    } else if v > 1.0 {
        1.0
    } else {
        v
    }
}

const fn max_f32(a: f32, b: f32) -> f32 {
    if a >= b {
        a
    } else {
        b
    }
}

/// Asymptotic-complexity classes recognised by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BigO {
    /// Constant time.
    O1,
    /// Logarithmic.
    OLogN,
    /// Linear.
    ON,
    /// Linearithmic.
    ONLogN,
    /// Quadratic.
    ON2,
    /// Cubic.
    ON3,
    /// Exponential / worse.
    OExp,
}

impl BigO {
    /// Human-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::O1 => "O(1)",
            Self::OLogN => "O(log n)",
            Self::ON => "O(n)",
            Self::ONLogN => "O(n log n)",
            Self::ON2 => "O(n^2)",
            Self::ON3 => "O(n^3)",
            Self::OExp => "O(2^n)",
        }
    }
}

/// CIA-triad impact axes — used by [`CostClaim::BugRisk`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Impact {
    /// Confidentiality impact, 0..=1.
    pub confidentiality: f32,
    /// Integrity impact, 0..=1.
    pub integrity: f32,
    /// Availability impact, 0..=1.
    pub availability: f32,
}

impl Impact {
    /// Construct an impact triple, clamping each axis to `[0.0, 1.0]`.
    #[must_use]
    pub const fn new(c: f32, i: f32, a: f32) -> Self {
        Self {
            confidentiality: clamp_unit(c),
            integrity: clamp_unit(i),
            availability: clamp_unit(a),
        }
    }

    /// Aggregate scalar (max of axes) for ranking.
    #[must_use]
    pub const fn worst_axis(self) -> f32 {
        max_f32(
            max_f32(self.confidentiality, self.integrity),
            self.availability,
        )
    }
}

/// What fixing this finding is worth, in concrete terms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CostClaim {
    /// Code-quality debt that compounds over time. Used for shape rules
    /// (R-FN-LEN, R-DUP, etc.).
    BlockingDebt {
        /// Relative weight of this debt item, higher is worse.
        weight: u32,
    },
    /// Asymptotic complexity claim — `O(N^2)` in `N=request_size` etc.
    Asymptotic {
        /// Big-O class.
        order: BigO,
        /// What `n` refers to.
        param: StaticStr,
        /// When this complexity bites in practice.
        scenario: StaticStr,
    },
    /// Runtime-ms claim grounded in real profile data.
    RuntimeMs {
        /// 50th-percentile observed wall time.
        observed_p50: f64,
        /// 95th-percentile observed wall time.
        observed_p95: f64,
        /// 99th-percentile observed wall time.
        observed_p99: f64,
        /// Number of profile traces consulted to compute the above.
        traces_consulted: u32,
    },
    /// Recurring monetary cost (e.g. unused paid-tier features).
    DollarsPerMonth {
        /// USD per month.
        estimate: f64,
        /// Provenance of the estimate.
        source: StaticStr,
    },
    /// Probability-weighted bug cost (taint hits, races).
    BugRisk {
        /// CWE id, if applicable.
        cwe: Option<u32>,
        /// 0..=1 estimate of how easily an attacker can trigger.
        exploitability: f32,
        /// CIA-triad impact.
        impact: Impact,
    },
}

impl CostClaim {
    /// Scalar score in the rough shape of "USD per month" — used as the
    /// `cost` factor of `cost × confidence` ranking.
    #[must_use]
    pub fn ranking_score(&self) -> f64 {
        match self {
            Self::BlockingDebt { weight } => f64::from(*weight) * 10.0,
            Self::Asymptotic { order, .. } => Self::big_o_weight(*order),
            Self::RuntimeMs { observed_p95, .. } => *observed_p95,
            Self::DollarsPerMonth { estimate, .. } => *estimate,
            Self::BugRisk {
                exploitability,
                impact,
                ..
            } => f64::from(*exploitability * impact.worst_axis()) * 1000.0,
        }
    }

    const fn big_o_weight(order: BigO) -> f64 {
        match order {
            BigO::O1 => 1.0,
            BigO::OLogN => 5.0,
            BigO::ON => 25.0,
            BigO::ONLogN => 100.0,
            BigO::ON2 => 500.0,
            BigO::ON3 => 2_500.0,
            BigO::OExp => 10_000.0,
        }
    }
}
