//! Canonical [`Finding`] schema for Clean Code V12.
//!
//! This crate is **pure data + builders + serde + suppress-key
//! derivation**. No I/O. The SARIF and `RDFormat` emitters live in the
//! sibling crates `cc-sarif` and `cc-rdformat`; this crate ships
//! [`SarifSink`] / [`RdJsonSink`] stubs only so callers can wire trait
//! objects without circular dependencies.
//!
//! # Self-host gate
//!
//! cc-finding is the dogfood candidate for **R-ERR-ACTION**: every
//! [`FindingError`] variant must say *what* went wrong **and** *how* to
//! fix it. Adding a new error variant without an actionable message is
//! a regression.
//!
//! # Schema versioning
//!
//! [`SCHEMA_VERSION`] is bumped on any non-additive change to the
//! [`Finding`] shape. Old SARIFs are rejected with migration advice
//! by `cc-sarif::ingest`.
//!
//! # File map
//!
//! | Module        | Purpose                                       |
//! |---------------|-----------------------------------------------|
//! | `error`       | [`FindingError`]                              |
//! | `severity`    | [`Severity`], [`Confidence`]                  |
//! | `category`    | [`Category`]                                  |
//! | `location`    | [`Location`], [`Position`], [`RelatedLocation`]|
//! | `message`     | [`ActionableMessage`], [`Remediation`]        |
//! | `evidence`    | [`Evidence`], dataflow paths                  |
//! | `cost`        | [`CostClaim`], [`BigO`], [`Impact`]           |
//! | `fix`         | [`FixProposal`], [`FixSafety`], [`TextEdit`]  |
//! | `version`     | [`ProbeVersion`], [`KernelVersion`]           |
//! | `finding`     | [`Finding`], [`FindingId`]                    |
//! | `suppress`    | [`SuppressKey`]                               |
//! | `builder`     | [`FindingBuilder`]                            |
//! | `summary`     | [`Summary`]                                   |
//! | `sink`        | [`FindingSink`] + reference impls             |

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod builder;
pub mod category;
pub mod cost;
pub mod error;
pub mod evidence;
pub mod finding;
pub mod fix;
pub mod location;
pub mod message;
pub mod severity;
pub mod sink;
pub mod summary;
pub mod suppress;
pub mod version;

pub use builder::FindingBuilder;
pub use category::Category;
pub use cost::{BigO, CostClaim, Impact};
pub use error::{FindingError, Result};
pub use evidence::{DataFlowPath, DataFlowStep, Evidence};
pub use finding::{Finding, FindingId};
pub use fix::{CodemodEngine, CodemodScope, FixProposal, FixSafety, PromptHash, Range, TextEdit};
pub use location::{GitRef, Location, NodeId, Position, RelatedLocation};
pub use message::{ActionableMessage, Remediation};
pub use severity::{Confidence, Severity};
pub use sink::{BaselineDiffSink, FindingSink, RdJsonSink, SarifSink, TtySink};
pub use summary::Summary;
pub use suppress::SuppressKey;
pub use version::{KernelVersion, ProbeVersion};

/// Schema-version constant. Bump on any non-additive change to the
/// [`Finding`] shape. Sibling crates (`cc-sarif`, `cc-rdformat`) read
/// this constant when validating archives on disk.
pub const SCHEMA_VERSION: u32 = 1;

/// Type alias for "string slot that is usually a probe-pack constant
/// but must round-trip through serde owned."
///
/// Probe authors construct findings with `&'static str` literals
/// (zero-alloc, no copy). Deserialised findings own their strings.
/// Both shapes share this type via [`std::borrow::Cow`].
pub type StaticStr = std::borrow::Cow<'static, str>;
