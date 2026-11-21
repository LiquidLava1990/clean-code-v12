//! Top-level rule taxonomy.

use serde::{Deserialize, Serialize};

/// Top-level category of a Finding. Aligned with the Clean-Code-V12
/// probe-pack family taxonomy.
///
/// The variant set is deliberately closed: new categories require a
/// schema bump to keep cross-version baselines stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Code shape — function length, file length, nesting depth.
    Shape,
    /// Slop — duplication, dead code, copy-paste smell.
    Slop,
    /// Performance — asymptotic or measured runtime regressions.
    Perf,
    /// Functional bugs — logic errors, off-by-ones.
    Bug,
    /// Taint analysis hits — untrusted input reaching a sink.
    Taint,
    /// Concurrency hazards — races, deadlocks, missing locks.
    Concurrent,
    /// Memory issues — leaks, UB, lifetime hazards.
    Memory,
    /// Dependency hygiene.
    Deps,
    /// Test quality and coverage.
    Test,
    /// Public API stability + ergonomics.
    Api,
    /// Database/SQL concerns.
    Db,
    /// Observability — logging, metrics, tracing.
    Obs,
    /// Operational concerns — runbooks, alerts, SLOs.
    Ops,
    /// Deployment + release pipeline.
    Deploy,
    /// Numerical correctness.
    Math,
    /// Internationalisation.
    I18n,
    /// Accessibility.
    A11y,
    /// Documentation completeness/accuracy.
    Docs,
    /// CI configuration + reliability.
    Ci,
    /// Code rot — abandoned modules, drifted contracts.
    Rot,
    /// Configuration hygiene.
    Config,
    /// Architecture violations — layering, boundaries, cycles.
    Arch,
    /// Compliance — license, regulatory.
    Compliance,
    /// Type-system soundness.
    Type,
    /// Fragility — flaky tests, brittle assertions.
    Fragile,
    /// Project layout conventions (boot path, manifests, typed events).
    Convention,
    /// Self-referential — findings about cc-finding itself.
    Meta,
}

impl Category {
    /// Lower-case canonical name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shape => "shape",
            Self::Slop => "slop",
            Self::Perf => "perf",
            Self::Bug => "bug",
            Self::Taint => "taint",
            Self::Concurrent => "concurrent",
            Self::Memory => "memory",
            Self::Deps => "deps",
            Self::Test => "test",
            Self::Api => "api",
            Self::Db => "db",
            Self::Obs => "obs",
            Self::Ops => "ops",
            Self::Deploy => "deploy",
            Self::Math => "math",
            Self::I18n => "i18n",
            Self::A11y => "a11y",
            Self::Docs => "docs",
            Self::Ci => "ci",
            Self::Rot => "rot",
            Self::Config => "config",
            Self::Arch => "arch",
            Self::Compliance => "compliance",
            Self::Type => "type",
            Self::Fragile => "fragile",
            Self::Convention => "convention",
            Self::Meta => "meta",
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
