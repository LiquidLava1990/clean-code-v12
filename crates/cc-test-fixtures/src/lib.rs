//! Clean Code V12 — golden fixture corpus for kernel + rule integration tests.
//!
//! This crate ships two faces of the same data:
//!
//! 1. A **Rust API** ([`FixtureCatalog`]) that exposes every fixture as
//!    embedded byte slices keyed by `(language, rule_id, kind)`.
//! 2. A **static directory tree** under `tests/fixtures/` containing
//!    real `.py` / `.ts` / `.go` / `.rs` files that downstream crates
//!    can copy or reference directly.
//!
//! Every Phase-1 rule should ideally carry a positive (violating) and
//! negative (clean) fixture across all four languages. Where that is
//! not possible (e.g. Rust has no class inheritance), the gap is
//! documented on [`catalog`] and [`FixtureCatalog::lookup`] returns
//! `None` for the missing triple.
//!
//! # Example
//!
//! ```
//! use cc_test_fixtures::{FixtureCatalog, FixtureKind, Language};
//!
//! let py = FixtureCatalog::lookup(
//!     Language::Python,
//!     "cc.shape.fn_length",
//!     FixtureKind::Violating,
//! )
//! .expect("python fn_length violating fixture must exist");
//! assert!(!py.source.is_empty());
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod catalog;
pub mod error;
pub mod languages;

pub use catalog::{write_to_tempdir, Fixture, FixtureCatalog, FixtureKind, Language};
pub use error::FixtureError;
