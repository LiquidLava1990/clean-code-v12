//! Runtime context handed to every [`Rule::run`](crate::Rule::run) call.
//!
//! [`RuleContext`] bundles the four inputs every probe needs: the CPG
//! batch, a [`SourceTable`] for byte-accurate snippets, the per-rule
//! config slice, the project fingerprint, and kernel metadata.
//!
//! All borrows are scoped to the lifetime of one rule invocation —
//! probes MUST NOT cache references between calls.

use std::collections::BTreeMap;
use std::fs;
use std::sync::RwLock;
use std::time::SystemTime;

use camino::{Utf8Path, Utf8PathBuf};
use cc_config::RuleConfig;
use cc_cpg::CpgWriteBatch;
use cc_finding::KernelVersion;
use uuid::Uuid;

/// Lookup table mapping repo-relative paths to source bytes.
///
/// Two implementations are provided:
///
/// - [`InMemorySourceTable`] — owns the bytes outright. Ideal for tests
///   and small repos.
/// - [`FileBackedSourceTable`] — reads + caches lazily off disk. If the
///   backing file is missing or unreadable, an empty slice is returned
///   and a warning is emitted via `tracing::warn!` — never a panic, so
///   a probe that tries to grep a vanished file degrades to silent
///   no-op rather than killing the kernel.
///
/// # Lifetime contract
///
/// Implementations return a `&'static [u8]` because the kernel keeps
/// source bytes alive for the entire run (and Phase 1 holds them in
/// the same arena). Probes MUST NOT cache the slice past the run.
pub trait SourceTable: Send + Sync {
    /// Fetch source bytes for `path`. Returns an empty slice when the
    /// path is unknown or unreadable.
    fn get(&self, path: &Utf8Path) -> &'static [u8];

    /// Return all paths currently materialised. Order is unspecified.
    fn paths(&self) -> Vec<Utf8PathBuf>;
}

/// In-memory [`SourceTable`] — owns its bytes outright.
///
/// Useful for unit tests and tiny corpora where the kernel has already
/// loaded every file into memory. Inserts leak the bytes via
/// [`Box::leak`] so the [`SourceTable::get`] return slice can be
/// `&'static [u8]` without copying or locking on the hot path.
#[derive(Debug, Default)]
pub struct InMemorySourceTable {
    files: RwLock<BTreeMap<Utf8PathBuf, &'static [u8]>>,
}

impl InMemorySourceTable {
    /// Build an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            files: RwLock::new(BTreeMap::new()),
        }
    }

    /// Insert (or replace) a file's bytes. The bytes are leaked into
    /// `'static` storage; reclaim happens at process exit.
    pub fn insert(&self, path: impl Into<Utf8PathBuf>, bytes: impl Into<Vec<u8>>) {
        let leaked: &'static [u8] = Box::leak(bytes.into().into_boxed_slice());
        if let Ok(mut files) = self.files.write() {
            files.insert(path.into(), leaked);
        }
    }
}

impl SourceTable for InMemorySourceTable {
    fn get(&self, path: &Utf8Path) -> &'static [u8] {
        self.files
            .read()
            .ok()
            .and_then(|files| files.get(path).copied())
            .unwrap_or(&[])
    }

    fn paths(&self) -> Vec<Utf8PathBuf> {
        self.files
            .read()
            .map(|files| files.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// File-backed [`SourceTable`] — reads lazily, caches forever.
///
/// On first access for a given path, the bytes are read from disk and
/// memoised (leaked into `'static` storage). Subsequent calls return
/// the cached slice. If the file is unreadable, an empty slice is
/// cached and a `tracing::warn!` event is emitted.
#[derive(Debug)]
pub struct FileBackedSourceTable {
    root: Utf8PathBuf,
    cache: RwLock<BTreeMap<Utf8PathBuf, &'static [u8]>>,
}

impl FileBackedSourceTable {
    /// Construct a new table rooted at `root`. Lookups treat their
    /// argument as repo-relative; `root` is prepended for the I/O.
    #[must_use]
    pub fn new(root: impl Into<Utf8PathBuf>) -> Self {
        Self {
            root: root.into(),
            cache: RwLock::new(BTreeMap::new()),
        }
    }

    fn read_file(&self, path: &Utf8Path) -> &'static [u8] {
        let absolute = self.root.join(path);
        match fs::read(absolute.as_std_path()) {
            Ok(bytes) => Box::leak(bytes.into_boxed_slice()),
            Err(err) => {
                tracing::warn!(
                    target: "cc_rules::source",
                    path = %path,
                    error_kind = ?err.kind(),
                    "source file unreadable; rule snippets will see empty bytes"
                );
                &[]
            }
        }
    }
}

impl SourceTable for FileBackedSourceTable {
    fn get(&self, path: &Utf8Path) -> &'static [u8] {
        if let Ok(cache) = self.cache.read() {
            if let Some(bytes) = cache.get(path) {
                return bytes;
            }
        }
        let bytes = self.read_file(path);
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(path.to_owned(), bytes);
        }
        bytes
    }

    fn paths(&self) -> Vec<Utf8PathBuf> {
        self.cache
            .read()
            .map(|cache| cache.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Project-wide statistical fingerprint.
///
/// Real implementation lives in `cc-fingerprint` (Phase 2 task W3.T6
/// in the executable plan). For Phase 1 the struct is an empty marker
/// so `RuleContext` has a stable shape; once the fingerprint crate
/// lands, this type will be replaced with a re-export.
///
/// # Contract (forward-looking)
///
/// - `naming_style: NamingDistribution` — entropy + abbreviation profile.
/// - `error_taxonomy: ErrorPatternMap` — canonical exception names.
/// - `layering: LayerGraph` — observed downward-only import graph.
/// - `test_style: TestStyleProfile` — naming + assertion conventions.
///
/// Probes consult the fingerprint to decide whether a finding is a
/// drift outlier (e.g. only flag a `snake_case` identifier in a
/// `camelCase` repo), not whether it is a Tier-0 violation.
#[derive(Debug, Default, Clone)]
pub struct ProjectFingerprint {
    _phantom: (),
}

impl ProjectFingerprint {
    /// Construct an empty placeholder fingerprint.
    #[must_use]
    pub const fn empty() -> Self {
        Self { _phantom: () }
    }
}

/// Kernel-side metadata accompanying every rule run.
///
/// Captured once per `cc check` invocation and shared with every rule
/// in that run. Used to stamp findings with the producing kernel
/// version and to correlate logs by `run_id`.
#[derive(Debug, Clone)]
pub struct KernelMeta {
    /// Run-scoped UUID v7 — sortable by start time.
    pub run_id: Uuid,
    /// Wall-clock time at the start of the run.
    pub started_at: SystemTime,
    /// Kernel semver string, sourced from `CARGO_PKG_VERSION`.
    pub kernel_version: KernelVersion,
}

impl KernelMeta {
    /// Build a fresh meta block for a new run.
    #[must_use]
    pub fn now() -> Self {
        Self {
            run_id: Uuid::now_v7(),
            started_at: SystemTime::now(),
            kernel_version: KernelVersion::current(),
        }
    }
}

impl Default for KernelMeta {
    fn default() -> Self {
        Self::now()
    }
}

/// Inputs handed to every [`Rule::run`](crate::Rule::run).
///
/// Phase 1 borrows a [`CpgWriteBatch`] directly because the persistent
/// `CpgStore` is not yet wired (W1.T3 lands later). When the store is
/// online, this field will be replaced with `&'a CpgStore` and the
/// migration will bump [`crate::KERNEL_API_VERSION`].
pub struct RuleContext<'a> {
    /// In-memory CPG produced by the language frontend for this file
    /// (or whole-repo batch for cross-file probes).
    pub batch: &'a CpgWriteBatch,
    /// Source bytes keyed by repo-relative path.
    pub source: &'a dyn SourceTable,
    /// Per-repo configuration slice for the rule about to run.
    pub config: &'a RuleConfig,
    /// Project-wide drift fingerprint.
    pub project: &'a ProjectFingerprint,
    /// Kernel metadata for this run.
    pub kernel: &'a KernelMeta,
}
