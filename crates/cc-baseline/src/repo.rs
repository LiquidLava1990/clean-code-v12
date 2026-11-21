//! [`BaselineRepo`] — read/write façade around [`crate::model::Baseline`].

use camino::Utf8Path;
use cc_finding::{Finding, SuppressKey};
use chrono::{DateTime, Utc};

use crate::error::{BaselineError, BaselineResult};
use crate::io::atomic_write;
use crate::model::{Baseline, BaselineEntry, SCHEMA_VERSION};

/// In-memory mutable view of an on-disk baseline.
///
/// Construct with [`BaselineRepo::open`] (reads JSON if present, falls
/// back to an empty baseline) or [`BaselineRepo::create`] (bulk-accept).
/// Persist with [`BaselineRepo::save`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineRepo {
    inner: Baseline,
}

impl BaselineRepo {
    /// Open the baseline at `path`. Missing files are NOT an error —
    /// they yield an empty baseline (the common first-run case).
    ///
    /// # Errors
    /// Returns [`BaselineError::Read`] for I/O failures other than
    /// `NotFound`, [`BaselineError::Serde`] for JSON corruption, and
    /// [`BaselineError::UnsupportedSchema`] for newer-than-supported
    /// schema versions.
    pub fn open(path: &Utf8Path) -> BaselineResult<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Self::from_bytes(path, &bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::empty()),
            Err(source) => Err(BaselineError::Read {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// In-memory empty repo (no on-disk file).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            inner: Baseline::empty(None),
        }
    }

    /// Bulk-accept every finding in `findings`. Used by
    /// `cc check --baseline-create`.
    #[must_use]
    pub fn create(findings: &[Finding], git_ref: Option<&str>, who: Option<&str>) -> Self {
        let mut repo = Self {
            inner: Baseline::empty(git_ref.map(str::to_owned)),
        };
        for f in findings {
            repo.accept(f, None, who.map(str::to_owned));
        }
        repo
    }

    fn from_bytes(path: &Utf8Path, bytes: &[u8]) -> BaselineResult<Self> {
        let inner: Baseline =
            serde_json::from_slice(bytes).map_err(|source| BaselineError::Serde {
                path: path.to_path_buf(),
                source,
            })?;
        if inner.schema_version > SCHEMA_VERSION {
            return Err(BaselineError::UnsupportedSchema {
                path: path.to_path_buf(),
                found: inner.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(Self { inner })
    }

    /// Borrow the underlying [`Baseline`].
    #[must_use]
    pub const fn baseline(&self) -> &Baseline {
        &self.inner
    }

    /// `true` iff `key` is present in the baseline.
    #[must_use]
    pub fn contains(&self, key: &SuppressKey) -> bool {
        self.inner.entries.contains_key(key)
    }

    /// Number of entries currently in the baseline.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.entries.len()
    }

    /// `true` iff the baseline has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.entries.is_empty()
    }

    /// Borrow the entry for `key` if present.
    #[must_use]
    pub fn get(&self, key: &SuppressKey) -> Option<&BaselineEntry> {
        self.inner.entries.get(key)
    }

    /// Accept `finding` into the baseline.
    ///
    /// Returns `true` iff this call inserted a new entry. If the key was
    /// already present, [`BaselineEntry::touch`] is invoked instead and
    /// `false` is returned (the existing acceptance metadata is kept).
    pub fn accept(
        &mut self,
        finding: &Finding,
        reason: Option<String>,
        who: Option<String>,
    ) -> bool {
        let key = finding.suppress_key;
        if let Some(entry) = self.inner.entries.get_mut(&key) {
            entry.touch();
            return false;
        }
        self.inner
            .entries
            .insert(key, BaselineEntry::from_finding(finding, reason, who));
        true
    }

    /// Bump `last_seen_at` and `seen_count` for `key` if present.
    ///
    /// No-op when the key is not in the baseline. Used by the diff path
    /// to record that a persisted finding was re-observed.
    pub fn touch(&mut self, key: &SuppressKey) {
        if let Some(entry) = self.inner.entries.get_mut(key) {
            entry.touch();
        }
    }

    /// Remove a single entry by `key`. Returns the dropped
    /// [`BaselineEntry`] when the key was present, `None` otherwise.
    ///
    /// Used by `cc baseline sync` (CLI) to drop resolved findings
    /// without taking the temporal `last_seen_at` round-trip that
    /// [`Self::prune_unseen_since`] uses.
    pub fn remove(&mut self, key: &SuppressKey) -> Option<BaselineEntry> {
        self.inner.entries.remove(key)
    }

    /// Bulk-remove every key in `keys`. Returns the keys actually
    /// removed (those that were present), in iteration order.
    pub fn remove_keys(&mut self, keys: &[SuppressKey]) -> Vec<SuppressKey> {
        let mut removed = Vec::with_capacity(keys.len());
        for k in keys {
            if self.inner.entries.remove(k).is_some() {
                removed.push(*k);
            }
        }
        removed
    }

    /// Remove every entry whose `last_seen_at` is strictly before
    /// `cutoff`. Returns the removed keys (sorted, `BTreeMap` iteration order).
    pub fn prune_unseen_since(&mut self, cutoff: DateTime<Utc>) -> Vec<SuppressKey> {
        let stale: Vec<SuppressKey> = self
            .inner
            .entries
            .iter()
            .filter(|(_, e)| e.last_seen_at < cutoff)
            .map(|(k, _)| *k)
            .collect();
        for k in &stale {
            self.inner.entries.remove(k);
        }
        stale
    }

    /// Merge `other` into `self`. For colliding keys, the entry with the
    /// later `last_seen_at` wins; `seen_count` is summed; `accepted_at`
    /// + `accepted_by` + `reason` follow the more-recently-seen entry.
    #[must_use]
    pub fn merge(mut self, other: Self) -> Self {
        for (key, incoming) in other.inner.entries {
            self.merge_entry(key, incoming);
        }
        self
    }

    fn merge_entry(&mut self, key: SuppressKey, incoming: BaselineEntry) {
        match self.inner.entries.get_mut(&key) {
            None => {
                self.inner.entries.insert(key, incoming);
            }
            Some(existing) => {
                let combined = incoming.seen_count.saturating_add(existing.seen_count);
                if incoming.last_seen_at > existing.last_seen_at {
                    *existing = incoming;
                }
                existing.seen_count = combined;
            }
        }
    }

    /// Persist the baseline to `path`. Atomic — see [`atomic_write`].
    ///
    /// # Errors
    /// Bubbles up [`BaselineError::Serde`] for encode failures and
    /// [`BaselineError::Write`] / [`BaselineError::Rename`] for I/O.
    pub fn save(&self, path: &Utf8Path) -> BaselineResult<()> {
        let bytes =
            serde_json::to_vec_pretty(&self.inner).map_err(|source| BaselineError::Serde {
                path: path.to_path_buf(),
                source,
            })?;
        atomic_write(path, &bytes)
    }
}

impl Default for BaselineRepo {
    fn default() -> Self {
        Self::empty()
    }
}
