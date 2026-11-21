//! Fluent [`FindingBuilder`] — validates required fields at `.build()`.

use std::borrow::Cow;

use crate::category::Category;
use crate::cost::CostClaim;
use crate::error::{FindingError, Result};
use crate::evidence::Evidence;
use crate::finding::{Finding, FindingId};
use crate::fix::FixProposal;
use crate::location::{GitRef, Location, RelatedLocation};
use crate::message::ActionableMessage;
use crate::severity::{Confidence, Severity};
use crate::suppress::SuppressKey;
use crate::version::{KernelVersion, ProbeVersion};
use crate::StaticStr;

/// Fluent builder for [`Finding`].
///
/// Required fields: `rule_id`, `category`, `location`, `message`,
/// `evidence`, `severity`, `cost`, `probe_version`. Missing any of
/// these causes [`Self::build`] to return [`FindingError::MissingField`].
///
/// `id` defaults to a fresh `UUIDv7`. `confidence` defaults to
/// [`Confidence::default`] (0.0). `suppress_key` is computed from the
/// final finding shape.
#[derive(Debug, Default)]
pub struct FindingBuilder {
    id: Option<FindingId>,
    rule_id: Option<StaticStr>,
    category: Option<Category>,
    subcategory: Option<StaticStr>,
    location: Option<Location>,
    related: Vec<RelatedLocation>,
    message: Option<ActionableMessage>,
    evidence: Option<Evidence>,
    severity: Option<Severity>,
    confidence: Option<Confidence>,
    cost: Option<CostClaim>,
    fix: Option<FixProposal>,
    introduced_at: Option<GitRef>,
    probe_version: Option<ProbeVersion>,
    kernel_version: Option<KernelVersion>,
}

impl FindingBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the auto-generated [`FindingId`].
    #[must_use]
    pub const fn id(mut self, id: FindingId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the rule slug.
    #[must_use]
    pub fn rule_id(mut self, rule_id: &'static str) -> Self {
        self.rule_id = Some(Cow::Borrowed(rule_id));
        self
    }

    /// Set the category.
    #[must_use]
    pub const fn category(mut self, category: Category) -> Self {
        self.category = Some(category);
        self
    }

    /// Set an optional subcategory.
    #[must_use]
    pub fn subcategory(mut self, sub: &'static str) -> Self {
        self.subcategory = Some(Cow::Borrowed(sub));
        self
    }

    /// Set the primary location.
    #[must_use]
    pub fn location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    /// Append a related location.
    #[must_use]
    pub fn related(mut self, rel: RelatedLocation) -> Self {
        self.related.push(rel);
        self
    }

    /// Set the actionable message.
    #[must_use]
    pub fn message(mut self, message: ActionableMessage) -> Self {
        self.message = Some(message);
        self
    }

    /// Set the evidence block.
    #[must_use]
    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Set the severity level.
    #[must_use]
    pub const fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Set the calibrated confidence (clamped to `[0, 1]`).
    #[must_use]
    pub const fn confidence(mut self, value: f32) -> Self {
        self.confidence = Some(Confidence::new(value));
        self
    }

    /// Set the cost claim.
    #[must_use]
    pub fn cost(mut self, cost: CostClaim) -> Self {
        self.cost = Some(cost);
        self
    }

    /// Attach an auto-fix proposal.
    #[must_use]
    pub fn fix(mut self, fix: FixProposal) -> Self {
        self.fix = Some(fix);
        self
    }

    /// Attach a git blame anchor.
    #[must_use]
    pub fn introduced_at(mut self, gr: GitRef) -> Self {
        self.introduced_at = Some(gr);
        self
    }

    /// Set the probe-pack version.
    #[must_use]
    pub fn probe_version(mut self, pv: ProbeVersion) -> Self {
        self.probe_version = Some(pv);
        self
    }

    /// Override the kernel version (defaults to [`KernelVersion::current`]).
    #[must_use]
    pub fn kernel_version(mut self, kv: KernelVersion) -> Self {
        self.kernel_version = Some(kv);
        self
    }

    /// Validate required fields and assemble the [`Finding`].
    ///
    /// # Errors
    /// Returns [`FindingError::MissingField`] when any required field
    /// has not been set.
    pub fn build(self) -> Result<Finding> {
        let mut finding = self.assemble()?;
        finding.suppress_key = SuppressKey::from_finding(&finding);
        Ok(finding)
    }

    fn assemble(self) -> Result<Finding> {
        Ok(Finding {
            id: self.id.unwrap_or_default(),
            rule_id: required(self.rule_id, "rule_id")?,
            category: required(self.category, "category")?,
            subcategory: self.subcategory,
            location: required(self.location, "location")?,
            related: self.related,
            message: required(self.message, "message")?,
            evidence: required(self.evidence, "evidence")?,
            severity: required(self.severity, "severity")?,
            confidence: self.confidence.unwrap_or_default(),
            cost: required(self.cost, "cost")?,
            fix: self.fix,
            suppress_key: SuppressKey::ZERO,
            introduced_at: self.introduced_at,
            probe_version: required(self.probe_version, "probe_version")?,
            kernel_version: self.kernel_version.unwrap_or_else(KernelVersion::current),
        })
    }
}

fn required<T>(opt: Option<T>, field: &'static str) -> Result<T> {
    opt.ok_or(FindingError::MissingField { field })
}
