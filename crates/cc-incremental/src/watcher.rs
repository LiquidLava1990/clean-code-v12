//! `notify`-backed file watcher that drives salsa input invalidation.
//!
//! On every `Modify` event the watcher re-reads the file, hashes its
//! bytes, and emits a [`WatcherEvent`] on a `tokio::sync::mpsc`
//! channel. Consumers (LSP server, daemon, integration tests) drive
//! the channel and call [`crate::CcDatabase::update_file`] when the
//! event reports a hash change.
//!
//! The watcher itself does **not** hold a `&mut CcDatabase` — that
//! would entangle the lifetime with the consumer's own borrow
//! discipline. Decoupling via a channel keeps the watcher composable
//! with both single-threaded test loops and multi-threaded daemons.

use std::path::Path;
use std::sync::Arc;

use camino::{Utf8Path, Utf8PathBuf};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::error::{IncrementalError, IncrementalResult};
use crate::inputs::ContentHash;

/// Event emitted on every observed file modification.
#[derive(Debug, Clone)]
pub struct WatcherEvent {
    /// Repo-relative path of the modified file.
    pub path: Utf8PathBuf,
    /// SHA-256 hash of the file's new contents.
    pub new_hash: ContentHash,
    /// New file content (bytes already decoded as UTF-8).
    pub content: String,
}

/// Handle keeping the watcher alive. Drop to stop watching.
pub struct WatcherHandle {
    /// Owned watcher; dropped to terminate the inotify/FSEvent loop.
    _watcher: RecommendedWatcher,
    /// Channel half consumers receive events from.
    pub events: mpsc::UnboundedReceiver<WatcherEvent>,
}

impl WatcherHandle {
    /// Start watching `root` recursively. Returns a handle whose
    /// `events` receiver yields one [`WatcherEvent`] per `Modify`.
    ///
    /// # Errors
    ///
    /// Returns [`IncrementalError::Watcher`] if `notify` cannot install
    /// the platform watcher (permissions, missing path, kernel out of
    /// inotify slots, etc.).
    pub fn start(root: &Utf8Path) -> IncrementalResult<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let root_for_handler: Arc<Utf8PathBuf> = Arc::new(root.to_owned());
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    for raw_path in event.paths {
                        if let Some(evt) = build_event(&raw_path, &root_for_handler) {
                            let _ = tx.send(evt);
                        }
                    }
                }
            }
        })
        .map_err(|e| IncrementalError::watcher("start", classify_notify_err(&e)))?;

        watcher
            .watch(root.as_std_path(), RecursiveMode::Recursive)
            .map_err(|e| IncrementalError::watcher("start", classify_notify_err(&e)))?;

        Ok(Self {
            _watcher: watcher,
            events: rx,
        })
    }
}

/// Build a [`WatcherEvent`] from a raw filesystem path. Reads bytes,
/// decodes UTF-8, hashes, and resolves the path relative to `root`.
/// Returns `None` if the file is not under `root`, is not UTF-8, or
/// cannot be read (the watcher should not propagate transient I/O
/// errors as fatal — those drop silently).
fn build_event(raw: &Path, root: &Utf8Path) -> Option<WatcherEvent> {
    let utf8 = Utf8Path::from_path(raw)?;
    let rel = utf8.strip_prefix(root).unwrap_or(utf8).to_owned();
    let bytes = std::fs::read(raw).ok()?;
    let content = String::from_utf8(bytes).ok()?;
    let new_hash = ContentHash::of(content.as_bytes());
    Some(WatcherEvent {
        path: rel,
        new_hash,
        content,
    })
}

/// R-05-safe classification of a `notify::Error`. We never surface the
/// foreign `Debug` repr of an upstream error (S10).
fn classify_notify_err(err: &notify::Error) -> String {
    match &err.kind {
        notify::ErrorKind::PathNotFound => "path-not-found".to_owned(),
        notify::ErrorKind::Generic(_) => "generic".to_owned(),
        notify::ErrorKind::Io(io_err) => format!("io:{:?}", io_err.kind()),
        notify::ErrorKind::WatchNotFound => "watch-not-found".to_owned(),
        notify::ErrorKind::InvalidConfig(_) => "invalid-config".to_owned(),
        notify::ErrorKind::MaxFilesWatch => "max-files-watch".to_owned(),
    }
}
