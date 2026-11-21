//! [`CacheStore`] trait + [`InMemoryCache`] default.
//!
//! Phase 1 ships an in-memory map. Phase 5 adds an on-disk redb cache
//! so judgments survive across CLI runs (the whole point of the
//! deterministic [`PromptCacheKey`]).

use std::collections::HashMap;
use std::sync::RwLock;

use crate::prompt::PromptCacheKey;
use crate::response::Judgment;

/// Storage backend for cached LLM judgments.
///
/// Implementations MUST be `Send + Sync`. They MUST NOT panic — a
/// cache failure is a soft failure (`get` returns `None`, `put` is a
/// no-op), so probes degrade to issuing a fresh LLM call.
pub trait CacheStore: Send + Sync {
    /// Look up a previously-cached judgment for `key`.
    fn get(&self, key: &PromptCacheKey) -> Option<Judgment>;

    /// Insert / replace a judgment for `key`.
    fn put(&self, key: PromptCacheKey, judgment: Judgment);
}

// ---------------------------------------------------------------------------
// InMemoryCache — Phase 1 default
// ---------------------------------------------------------------------------

/// Process-local cache backed by an `RwLock<HashMap>`.
///
/// Survives only for the lifetime of the kernel process. Suitable for
/// unit tests and single-CLI-invocation runs where the same prompt
/// fires across many probes.
#[derive(Debug, Default)]
pub struct InMemoryCache {
    inner: RwLock<HashMap<PromptCacheKey, Judgment>>,
}

impl InMemoryCache {
    /// Construct an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries currently held. Returns 0 if poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` when no entries are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CacheStore for InMemoryCache {
    fn get(&self, key: &PromptCacheKey) -> Option<Judgment> {
        // Poisoned lock = soft miss. Probe re-issues the LLM call.
        self.inner
            .read()
            .ok()
            .and_then(|guard| guard.get(key).cloned())
    }

    fn put(&self, key: PromptCacheKey, judgment: Judgment) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(key, judgment);
        } else {
            tracing::error!("InMemoryCache lock poisoned; cache put dropped");
        }
    }
}
