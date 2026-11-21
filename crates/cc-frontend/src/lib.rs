//! `cc-frontend` — language-agnostic frontend trait and shared lift helpers
//! for Clean Code V12.
//!
//! This crate defines the [`LanguageFrontend`] trait that every per-language
//! frontend (`cc-frontend-python`, `cc-frontend-typescript`,
//! `cc-frontend-go`, `cc-frontend-rust`) implements, plus the shared
//! infrastructure those frontends use:
//!
//! - [`TreeSitterTree`] — opaque tree-sitter tree wrapper (no raw re-export).
//! - [`FileId`] — stable per-file identifier.
//! - [`LanguageRegistry`] / [`FrontendCore`] — registry + orchestrator the
//!   kernel uses to dispatch to the right frontend.
//! - [`lift_helpers`] — shared `block_to_node`, `branch_to_node`,
//!   `loop_to_node`, `try_to_node`, `position_from_ts_range`,
//!   `range_from_ts_range`, `intern_string`.
//! - [`default_resolver`] — lexical-scope name resolver used when a
//!   frontend doesn't override [`LanguageFrontend::resolve_names`].
//!
//! See `docs/design/CPG_SCHEMA.md` for the design contract.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod call_resolver;
pub mod default_resolver;
pub mod errors;
mod frontend;
pub mod lift_helpers;
pub mod query;
mod registry;
mod tree;
pub mod visibility;

pub use errors::{FrontendError, LiftError, ParseError, ParseErrorKind, ResolveError};
pub use frontend::{FileId, LanguageFrontend};
pub use registry::{FrontendCore, LanguageRegistry};
pub use tree::{LanguageId, TreeSitterTree};
