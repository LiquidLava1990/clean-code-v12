//! `cc-lsp` — Clean Code V12 Language Server Protocol daemon.
//!
//! The crate exposes the `cc-lsp` stdio binary plus a small library
//! surface so editor integrations and tests can construct a server in
//! the same address space (handy for `tower-lsp`'s `LspService` test
//! harness).
//!
//! # Public surface
//!
//! - [`Analyser`] — owns the [`cc_incremental::CcDatabase`], registers
//!   every Phase-1 frontend + the Tier-0 rule pack, and exposes a
//!   single [`Analyser::analyse`] entry point.
//! - [`CcLspServer`] — the [`tower_lsp::LanguageServer`] implementation.
//! - [`finding_to_diagnostic`] — the [`cc_finding::Finding`] →
//!   [`tower_lsp::lsp_types::Diagnostic`] mapping (also used by tests).
//! - [`LspError`] / [`LspResult`] — error surface.
//!
//! # Phase-1 deviations
//!
//! - Document sync is `FULL` (the editor sends the entire buffer on every
//!   change). Incremental LSP sync is deferred — `cc-incremental` already
//!   caches on `content_hash`, so we get most of the savings.
//! - `code_action_provider` advertises `Simple(true)` — Phase 11 ships
//!   suppress quick-fixes plus description-only rewrite actions; real
//!   `WorkspaceEdit` emission for `Remediation::AutoFix(FixProposal::Diff)`
//!   follows once the finding-cache is wired.
//! - Non-`file:` URIs (`untitled:`, `git:`, …) are rejected with a
//!   recoverable [`LspError::InvalidUri`] — they will be supported when
//!   Phase 4 wires unsaved-buffer storage.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod analyser;
pub mod code_actions;
pub mod diagnostics;
pub mod error;
pub mod server;

pub use analyser::Analyser;
pub use code_actions::{
    build_code_actions, build_suppress_action, REWRITE_TITLE_PREFIX, SUPPRESS_TITLE_PREFIX,
};
pub use diagnostics::{finding_to_diagnostic, severity_to_diagnostic_severity, DIAGNOSTIC_SOURCE};
pub use error::{LspError, LspResult};
pub use server::CcLspServer;
