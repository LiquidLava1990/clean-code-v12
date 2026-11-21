//! Error type for the LSP daemon.
//!
//! Every variant follows the R-ERR-ACTION shape: the [`std::fmt::Display`]
//! impl on each variant names *what* went wrong AND *how* a caller should
//! fix it. This is the dogfood gate the rest of the workspace also
//! enforces — see `cc-finding`'s `R-ERR-ACTION` doctrine note.

use thiserror::Error;

/// Result alias used throughout `cc-lsp`.
pub type LspResult<T> = std::result::Result<T, LspError>;

/// Errors produced inside the LSP server.
///
/// Every variant pairs the failure surface with a remediation hint so the
/// operator (or the editor sending the request) sees an actionable
/// diagnostic — never a bare "something went wrong".
#[derive(Debug, Error)]
pub enum LspError {
    /// A pack registration call into [`cc_rules::RuleRegistry`] failed.
    /// Almost always indicates a duplicate-pack-id bug at boot.
    #[error(
        "failed to register rule pack '{pack_id}': {source} — \
         remove the duplicate registration in `Analyser::new` or supply a \
         distinct pack id"
    )]
    RuleRegistration {
        /// Pack id that failed to register.
        pack_id: &'static str,
        /// Underlying registry error.
        #[source]
        source: cc_rules::RegistryError,
    },

    /// A document URI from the LSP client could not be turned into a
    /// repo-relative path.
    #[error(
        "could not derive a path from URI '{uri}': {reason} — \
         ask the client to send a `file://` URI rooted in a real workspace"
    )]
    InvalidUri {
        /// The URI that failed to parse.
        uri: String,
        /// What about the URI was wrong.
        reason: &'static str,
    },

    /// The server received a document for a language with no registered
    /// frontend (e.g. `.rb`).
    #[error(
        "no frontend registered for extension '{extension}' \
         (uri='{uri}') — ignore the file or add a frontend that claims \
         this extension to `Analyser::new`"
    )]
    UnsupportedLanguage {
        /// Lower-cased file extension (without leading dot) that was rejected.
        extension: String,
        /// URI of the document that triggered the rejection.
        uri: String,
    },
}
