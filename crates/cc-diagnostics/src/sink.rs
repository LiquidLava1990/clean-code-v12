//! [`DiagnosticSink`] trait + two reference implementations.
//!
//! - [`TracingSink`] — forwards to `tracing` macros (production default)
//! - [`CollectingSink`] — buffers into a `Vec` for tests / replay

use std::sync::RwLock;

use crate::diagnostic::Diagnostic;
use crate::level::Level;

/// Trait implemented by every diagnostic emission target.
///
/// Implementations MUST be `Send + Sync` so the kernel can share a
/// single `Arc<dyn DiagnosticSink>` across rayon worker threads.
///
/// `accept` swallows its own errors — diagnostics about diagnostics
/// would be a feedback loop. Sinks log internal failures via `tracing`
/// and move on.
pub trait DiagnosticSink: Send + Sync {
    /// Receive a diagnostic. Implementations must not panic.
    fn accept(&self, diag: Diagnostic);
}

// ---------------------------------------------------------------------------
// TracingSink — production default
// ---------------------------------------------------------------------------

/// Default sink — maps each [`Level`] to the matching `tracing` macro.
///
/// Wire this once at boot in `cc-cli`; everything routed through the
/// kernel diagnostic channel will surface in normal `tracing`
/// subscribers (JSON, env-filter, OTLP exporters).
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingSink;

impl TracingSink {
    /// Construct a tracing-backed sink.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl DiagnosticSink for TracingSink {
    fn accept(&self, diag: Diagnostic) {
        let code = diag.code;
        let source = diag.source.tag();
        let probe_id = diag.probe_id.as_deref().unwrap_or("-");
        let location = diag
            .location
            .as_deref()
            .map_or("-", camino::Utf8Path::as_str);

        match diag.level {
            Level::Trace => {
                tracing::trace!(code, source, probe_id, location, "{}", diag.message);
            }
            Level::Debug => {
                tracing::debug!(code, source, probe_id, location, "{}", diag.message);
            }
            Level::Info => {
                tracing::info!(code, source, probe_id, location, "{}", diag.message);
            }
            Level::Warn => {
                tracing::warn!(code, source, probe_id, location, "{}", diag.message);
            }
            Level::Error => {
                tracing::error!(code, source, probe_id, location, "{}", diag.message);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CollectingSink — for tests + replay
// ---------------------------------------------------------------------------

/// Buffering sink — accumulates diagnostics for inspection.
///
/// Intended for unit tests, integration tests, and the future
/// `--diagnostics-json` CLI flag. NOT for production hot paths
/// (unbounded growth).
#[derive(Debug, Default)]
pub struct CollectingSink {
    buffer: RwLock<Vec<Diagnostic>>,
}

impl CollectingSink {
    /// Construct an empty collecting sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the current buffer (clone). Useful for assertions.
    ///
    /// Returns an empty vec if the lock is poisoned — failing-open
    /// matches the "no panics in sinks" contract.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Diagnostic> {
        self.buffer
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Drain the buffer, returning all diagnostics collected so far.
    ///
    /// Returns an empty vec if the lock is poisoned.
    #[must_use]
    pub fn drain(&self) -> Vec<Diagnostic> {
        self.buffer
            .write()
            .map(|mut guard| std::mem::take(&mut *guard))
            .unwrap_or_default()
    }

    /// Number of diagnostics currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.read().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` when no diagnostics have been collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DiagnosticSink for CollectingSink {
    fn accept(&self, diag: Diagnostic) {
        // Lock poisoning is non-fatal: skip the diagnostic and log via
        // tracing rather than propagate a panic into worker threads.
        if let Ok(mut guard) = self.buffer.write() {
            guard.push(diag);
        } else {
            tracing::error!("CollectingSink lock poisoned; diagnostic dropped");
        }
    }
}
