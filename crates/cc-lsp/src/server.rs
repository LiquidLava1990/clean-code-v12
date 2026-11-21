//! [`CcLspServer`] — the [`tower_lsp::LanguageServer`] implementation.
//!
//! Phase-1 surface:
//!
//! - `initialize` advertises full-document sync and no provider yet
//!   (definitions / code-actions land in Phase 5).
//! - `did_open` / `did_change` / `did_save` re-run the analyser and
//!   publish diagnostics.
//! - `did_close` clears diagnostics for the closed document.
//! - `shutdown` is a no-op (the daemon owns no external resources).
//!
//! The server holds the [`crate::Analyser`] behind a tokio mutex because
//! salsa input updates need `&mut self`. Editor protocol traffic itself
//! is parallel — only the analysis pass serialises.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use cc_finding::Finding;
use tokio::sync::Mutex;
use tower_lsp::jsonrpc;
use tower_lsp::lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    Diagnostic, DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DidSaveTextDocumentParams, InitializeParams, InitializeResult, InitializedParams, MessageType,
    OneOf, ServerCapabilities, ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind, Url,
};
use tower_lsp::{Client, LanguageServer};

use crate::analyser::Analyser;
use crate::code_actions::build_code_actions;
use crate::diagnostics::finding_to_diagnostic;
use crate::error::LspError;

/// Per-document state cached between an analyser pass and a later
/// `textDocument/codeAction` request.
///
/// We hold the buffer text + the finding set so `code_action` can build
/// edits + match diagnostics back to findings without re-running analysis
/// (which would deadlock against the analyser mutex on every keystroke).
#[derive(Debug, Clone)]
struct DocumentState {
    text: String,
    findings: Vec<Finding>,
}

/// LSP server state.
///
/// `Arc<Mutex<Analyser>>` lets the construction site share a single
/// analyser across the lifetime of the daemon while still allowing
/// `&mut self` for salsa input updates inside async handlers.
///
/// `documents` is guarded by a synchronous `std::sync::Mutex` because the
/// access pattern is "lock, mutate map, unlock" — no awaits — and the
/// blocking time is bounded by a single `HashMap` insert/remove. Using a
/// sync mutex keeps the editor protocol fast-path zero-await on cache
/// reads inside `code_action`.
pub struct CcLspServer {
    client: Client,
    analyser: Arc<Mutex<Analyser>>,
    documents: Arc<StdMutex<HashMap<Url, DocumentState>>>,
}

impl CcLspServer {
    /// Build a new server bound to `client`, sharing `analyser`.
    #[must_use]
    pub fn new(client: Client, analyser: Arc<Mutex<Analyser>>) -> Self {
        Self {
            client,
            analyser,
            documents: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// Run the analyser against `text` for `uri` and publish the result.
    ///
    /// On a recoverable analyser error (unsupported language, malformed
    /// URI) we publish an empty diagnostic vector so the editor clears
    /// any stale squigglies and surface a `MessageType::WARNING` once.
    /// Hard errors propagate via the LSP `client.log_message` channel —
    /// the protocol has no good place to surface them per-request.
    async fn refresh(&self, uri: Url, text: String, version: Option<i32>) {
        let findings = self.compute_findings(&uri, &text).await;
        let diagnostics: Vec<Diagnostic> = findings.iter().map(finding_to_diagnostic).collect();
        self.cache_document(uri.clone(), text, findings);
        self.client
            .publish_diagnostics(uri, diagnostics, version)
            .await;
    }

    /// Compute findings for one document. Errors are logged to the
    /// client; on failure the caller still publishes (empty) diagnostics
    /// so stale markers do not stick around in the editor.
    async fn compute_findings(&self, uri: &Url, text: &str) -> Vec<Finding> {
        let outcome = {
            let mut analyser = self.analyser.lock().await;
            analyser.analyse(uri, text)
        };
        match outcome {
            Ok(findings) => findings,
            Err(err) => {
                self.log_recoverable(&err).await;
                Vec::new()
            }
        }
    }

    /// Persist the latest analyse pass so a later `code_action` request
    /// can match diagnostics back to findings without re-running analysis.
    fn cache_document(&self, uri: Url, text: String, findings: Vec<Finding>) {
        if let Ok(mut docs) = self.documents.lock() {
            docs.insert(uri, DocumentState { text, findings });
        }
    }

    /// Drop cached state for a closed document. Called from `did_close`
    /// to keep the documents map bounded.
    fn forget_document(&self, uri: &Url) {
        if let Ok(mut docs) = self.documents.lock() {
            docs.remove(uri);
        }
    }

    /// Clone the cached state for `uri`. Returns `None` when the document
    /// has not been analysed yet (or the lock is poisoned, in which case
    /// `code_action` degrades to "no actions" rather than panicking).
    fn snapshot_document(&self, uri: &Url) -> Option<DocumentState> {
        self.documents.lock().ok()?.get(uri).cloned()
    }

    /// Surface a recoverable analyser error through the LSP log channel.
    ///
    /// `LspError::UnsupportedLanguage` is downgraded to `INFO` (it's the
    /// expected outcome when the user opens a `.md` or `.txt` file in a
    /// workspace that has `cc-lsp` running). Everything else is `WARNING`.
    async fn log_recoverable(&self, err: &LspError) {
        let level = match err {
            LspError::UnsupportedLanguage { .. } => MessageType::INFO,
            _ => MessageType::WARNING,
        };
        self.client.log_message(level, err.to_string()).await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for CcLspServer {
    async fn initialize(&self, _: InitializeParams) -> jsonrpc::Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: build_capabilities(),
            server_info: Some(ServerInfo {
                name: "cc-lsp".to_owned(),
                version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "cc-lsp initialised")
            .await;
    }

    async fn shutdown(&self) -> jsonrpc::Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let doc = params.text_document;
        self.refresh(doc.uri, doc.text, Some(doc.version)).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let version = Some(params.text_document.version);
        // FULL sync — the last (only) content change carries the whole file.
        let Some(change) = params.content_changes.into_iter().last() else {
            return;
        };
        self.refresh(uri, change.text, version).await;
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        // Editors that send `text` on save get a refresh; otherwise the
        // last `did_change` already painted the right diagnostics.
        if let Some(text) = params.text {
            self.refresh(params.text_document.uri, text, None).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.forget_document(&uri);
        self.client.publish_diagnostics(uri, Vec::new(), None).await;
    }

    async fn code_action(
        &self,
        params: CodeActionParams,
    ) -> jsonrpc::Result<Option<CodeActionResponse>> {
        let uri = params.text_document.uri;
        let Some(state) = self.snapshot_document(&uri) else {
            // No cached analysis — usually means the editor sent a
            // `code_action` before any `did_open`/`did_change`, or for a
            // virtual buffer we cannot analyse. Return an empty list
            // (LSP-spec-correct) instead of erroring.
            return Ok(Some(Vec::<CodeActionOrCommand>::new()));
        };
        let actions = build_code_actions(
            &uri,
            &state.text,
            params.range,
            &params.context,
            &state.findings,
        );
        Ok(Some(actions))
    }
}

/// Build the capability set advertised in `initialize`.
///
/// Phase 11 advertises `code_action_provider = Simple(true)` so editors
/// surface the `cc:` quick-fix lightbulb. Definition / inline-fix
/// affordances stay unset until the cross-reference and edit-emission
/// passes land.
fn build_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        definition_provider: None,
        code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
        diagnostic_provider: None,
        workspace: Some(workspace_capabilities()),
        ..ServerCapabilities::default()
    }
}

/// Minimal workspace capability block — declares we do not require
/// per-folder configuration but accept multi-root workspaces.
const fn workspace_capabilities() -> tower_lsp::lsp_types::WorkspaceServerCapabilities {
    tower_lsp::lsp_types::WorkspaceServerCapabilities {
        workspace_folders: Some(tower_lsp::lsp_types::WorkspaceFoldersServerCapabilities {
            supported: Some(true),
            change_notifications: Some(OneOf::Left(true)),
        }),
        file_operations: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_advertise_full_text_sync() {
        let caps = build_capabilities();
        match caps.text_document_sync {
            Some(TextDocumentSyncCapability::Kind(kind)) => {
                assert_eq!(kind, TextDocumentSyncKind::FULL);
            }
            other => panic!("expected Kind(FULL); got {other:?}"),
        }
    }

    #[test]
    fn capabilities_advertise_code_actions() {
        let caps = build_capabilities();
        assert!(
            caps.definition_provider.is_none(),
            "definition still deferred"
        );
        match caps.code_action_provider {
            Some(CodeActionProviderCapability::Simple(true)) => {}
            other => panic!("expected Simple(true) code_action_provider; got {other:?}"),
        }
    }
}
