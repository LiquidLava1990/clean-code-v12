//! [`CcDatabase`] — the salsa-backed incremental analysis database.
//!
//! The database owns:
//!
//! 1. Salsa storage (the cache that backs every tracked query).
//! 2. A frontend registry (which frontend handles which language).
//! 3. A rule registry slice (which rules to run in `findings_for`).
//! 4. A `path -> FileInput` index so the watcher can re-hash on modify
//!    events and call [`CcDatabase::update_file`] without re-allocating
//!    a `FileInput`.
//!
//! # Trait split
//!
//! Salsa free functions take `db: &dyn CcDb`. [`CcDb`] is the trait that
//! exposes both the salsa surface (`salsa::Database`) and our domain
//! helpers (`parse_with_frontend`, `lift_with_frontend`,
//! `run_rules_with_inputs`, `lookup_file_id`). Concrete impls live on
//! [`CcDatabase`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use camino::{Utf8Path, Utf8PathBuf};
use cc_cpg::CpgWriteBatch;
use cc_frontend::{FileId, FrontendCore, TreeSitterTree};
use cc_rules::{KernelMeta, ProjectFingerprint, Rule, RuleContext, SourceTable};

use crate::inputs::{ContentHash, FileInput, RepoInput, RuleInput, Utf8PathBufWrap};

/// Salsa-aware database trait — combines `salsa::Database` with the
/// domain helpers tracked queries call.
#[salsa::db]
pub trait CcDb: salsa::Database {
    /// Parse `content` using the registered frontend for `language`.
    fn parse_with_frontend(&self, language: &str, content: &str) -> TreeSitterTree;

    /// Lift `tree` for `language` into a fresh [`CpgWriteBatch`].
    fn lift_with_frontend(
        &self,
        language: &str,
        tree: &TreeSitterTree,
        content: &str,
        file: FileInput,
    ) -> CpgWriteBatch;

    /// Run every registered rule against `batch` and return the
    /// concatenated findings.
    fn run_rules_with_inputs(
        &self,
        batch: &CpgWriteBatch,
        path: &Utf8Path,
    ) -> Vec<cc_finding::Finding>;

    /// Resolve a stored salsa file-id back into a [`FileInput`].
    fn lookup_file_id(&self, id: u64) -> Option<FileInput>;
}

/// Side-channel registry held by [`CcDatabase`] so tracked queries can
/// reach frontends, rules, and the [`FileInput`] id index without taking
/// them through salsa (they're not values — they're machinery).
#[derive(Default)]
struct DbState {
    frontends: Option<Arc<FrontendCore>>,
    rules: Vec<&'static dyn Rule>,
    rule_pack_id: &'static str,
    by_path: BTreeMap<Utf8PathBuf, FileInput>,
    by_id: BTreeMap<u64, FileInput>,
    /// Monotonic counter for synthesizing `cc_frontend::FileId`s. Stable
    /// across a single `CcDatabase` lifetime.
    next_file_id: u64,
}

/// Salsa-backed incremental analysis database.
///
/// Cloning is **not** cheap — salsa storage is per-database, so a clone
/// produces an independent cache. Construct one per long-lived process
/// (LSP server, daemon) and share `&CcDatabase` for queries; take
/// `&mut CcDatabase` only when registering or updating inputs.
#[salsa::db]
pub struct CcDatabase {
    storage: salsa::Storage<Self>,
    state: Mutex<DbState>,
}

impl Default for CcDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for CcDatabase {
    fn clone(&self) -> Self {
        // Salsa Storage clones; the side-channel state is recreated
        // empty on a clone, so callers must re-register frontends/rules.
        // (We could deep-copy `DbState`, but it would silently desync if
        // a clone outlives a registration update on the original.)
        Self {
            storage: self.storage.clone(),
            state: Mutex::new(DbState::default()),
        }
    }
}

impl CcDatabase {
    /// Construct a fresh database with no frontends or rules registered.
    #[must_use]
    pub fn new() -> Self {
        Self {
            storage: salsa::Storage::default(),
            state: Mutex::new(DbState::default()),
        }
    }

    /// Register the frontend orchestrator. The `FrontendCore` already
    /// bundles a `LanguageRegistry` keyed by language name.
    pub fn register_frontends(&mut self, core: Arc<FrontendCore>) {
        if let Ok(mut state) = self.state.lock() {
            state.frontends = Some(core);
        }
    }

    /// Register a rule pack — the rules are run in-order against every
    /// file's CPG batch in [`fn@crate::queries::findings_for`].
    pub fn register_rules(&mut self, pack_id: &'static str, rules: Vec<&'static dyn Rule>) {
        if let Ok(mut state) = self.state.lock() {
            state.rule_pack_id = pack_id;
            state.rules = rules;
        }
    }

    /// Register a [`RuleInput`] — caller-side handle for invalidating
    /// findings when a probe pack version bumps.
    #[must_use]
    pub fn add_rule_input(&mut self, rule_id: &str, pack_semver: &str) -> RuleInput {
        RuleInput::new(self, rule_id.to_owned(), pack_semver.to_owned())
    }

    /// Register or replace a file. Returns the [`FileInput`] handle.
    ///
    /// If the path is already registered, the existing input is reused
    /// (and its content/hash are updated to match the new bytes).
    pub fn add_file(
        &mut self,
        path: impl Into<Utf8PathBuf>,
        content: impl Into<String>,
        language: impl Into<String>,
    ) -> FileInput {
        let path = path.into();
        let content = content.into();
        let language = language.into();
        let hash = ContentHash::of(content.as_bytes());

        if let Some(existing) = self.lookup_path(&path) {
            // Path already registered — update fields via Setter.
            use salsa::Setter;
            existing.set_content_hash(self).to(hash);
            existing.set_content(self).to(content);
            existing.set_language(self).to(language);
            return existing;
        }

        let file = FileInput::new(self, Utf8PathBufWrap(path.clone()), hash, content, language);
        let id = file_input_raw_id(file);
        if let Ok(mut state) = self.state.lock() {
            state.by_path.insert(path, file);
            state.by_id.insert(id, file);
        }
        file
    }

    /// Update a file's content. Returns `true` iff the new content's
    /// hash differs from the previous one — i.e. iff the change will
    /// actually invalidate downstream queries.
    pub fn update_file(&mut self, file: FileInput, new_content: impl Into<String>) -> bool {
        use salsa::Setter;
        let new_content = new_content.into();
        let new_hash = ContentHash::of(new_content.as_bytes());
        let old_hash = file.content_hash(self);
        if old_hash == new_hash {
            return false;
        }
        file.set_content_hash(self).to(new_hash);
        file.set_content(self).to(new_content);
        true
    }

    /// Remove a file from the database. Subsequent queries against the
    /// returned `FileInput` will use stale-but-cached values; the path
    /// index drops the entry so the watcher will not re-touch it.
    pub fn remove_file(&mut self, file: FileInput) {
        let id = file_input_raw_id(file);
        if let Ok(mut state) = self.state.lock() {
            // Strip the path mapping so the watcher re-add path silently
            // creates a new FileInput rather than reusing a stale one.
            state.by_path.retain(|_, v| file_input_raw_id(*v) != id);
            state.by_id.remove(&id);
        }
    }

    /// Look up an existing [`FileInput`] by repo-relative path.
    #[must_use]
    pub fn lookup_path(&self, path: &Utf8Path) -> Option<FileInput> {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.by_path.get(path).copied())
    }

    /// Build a [`RepoInput`] over the currently-registered files.
    #[must_use]
    pub fn build_repo_input(&mut self, root: impl Into<Utf8PathBuf>) -> RepoInput {
        let ids: std::collections::BTreeSet<u64> = self
            .state
            .lock()
            .ok()
            .map(|s| s.by_id.keys().copied().collect())
            .unwrap_or_default();
        RepoInput::new(self, Utf8PathBufWrap(root.into()), ids)
    }

    /// Convenience accessor — runs the `parsed_tree` query.
    pub fn parsed_tree(&self, file: FileInput) -> crate::queries::CachedTree {
        crate::queries::parsed_tree(self, file)
    }

    /// Convenience accessor — runs the `cpg_root` query.
    pub fn cpg_root(&self, file: FileInput) -> crate::queries::CachedCpg {
        crate::queries::cpg_root(self, file)
    }

    /// Convenience accessor — runs the `findings_for` query.
    pub fn findings_for(&self, file: FileInput) -> crate::queries::CachedFindings {
        crate::queries::findings_for(self, file)
    }

    /// Convenience accessor — runs the `health_score_for_file` query.
    pub fn health_score_for_file(&self, file: FileInput) -> f64 {
        crate::queries::health_score_for_file(self, file)
    }

    /// Convenience accessor — runs the `repo_health_score` query.
    pub fn repo_health_score(&self, repo: RepoInput) -> f64 {
        crate::queries::repo_health_score(self, repo)
    }

    /// Allocate the next `cc_frontend::FileId` for a freshly-registered
    /// path. Stable across a single `CcDatabase` lifetime; not cross-process.
    fn next_frontend_file_id(&self) -> FileId {
        let mut state = self
            .state
            .lock()
            .expect("CcDatabase state mutex poisoned — fatal");
        state.next_file_id += 1;
        FileId::new(state.next_file_id)
    }

    /// Run `op` against the registered frontend for `language`, returning
    /// `op`'s output. Yields `None` when the state mutex is poisoned, no
    /// `FrontendCore` is registered, the language has no matching
    /// frontend, or `op` itself returns `None` — callers fall back to
    /// a no-op tree / empty batch.
    fn with_frontend<R>(
        &self,
        language: &str,
        op: impl FnOnce(&dyn cc_frontend::LanguageFrontend) -> Option<R>,
    ) -> Option<R> {
        let core = self.state.lock().ok().and_then(|s| s.frontends.clone())?;
        let frontend = core.registry().for_language(language)?;
        op(frontend)
    }
}

#[salsa::db]
impl salsa::Database for CcDatabase {
    fn salsa_event(&self, event: &dyn Fn() -> salsa::Event) {
        // Cheap: only materialise the event when tracing is enabled at
        // debug level, and never with `Debug` formatting on untrusted
        // inputs (S10 R-05 — `event` borrows internal salsa state, no
        // foreign data).
        if tracing::enabled!(target: "salsa", tracing::Level::DEBUG) {
            tracing::debug!(target: "salsa", kind = ?event().kind);
        }
    }
}

#[salsa::db]
impl CcDb for CcDatabase {
    fn parse_with_frontend(&self, language: &str, content: &str) -> TreeSitterTree {
        self.with_frontend(language, |frontend| frontend.parse(content).ok())
            .unwrap_or_else(|| empty_tree(language))
    }

    fn lift_with_frontend(
        &self,
        language: &str,
        tree: &TreeSitterTree,
        content: &str,
        _file: FileInput,
    ) -> CpgWriteBatch {
        let mut batch = CpgWriteBatch::new();
        let file_id = self.next_frontend_file_id();
        self.with_frontend(language, |frontend| {
            let _ = frontend.lift(tree, content, &mut batch, file_id);
            Some(())
        });
        batch
    }

    fn run_rules_with_inputs(
        &self,
        batch: &CpgWriteBatch,
        path: &Utf8Path,
    ) -> Vec<cc_finding::Finding> {
        let (rules, pack_id) = {
            let Ok(state) = self.state.lock() else {
                return Vec::new();
            };
            (state.rules.clone(), state.rule_pack_id)
        };
        if rules.is_empty() {
            return Vec::new();
        }
        let source = empty_source_table_for(path);
        let config = cc_config::RuleConfig::default();
        let project = ProjectFingerprint::empty();
        let kernel = KernelMeta::now();
        let ctx = RuleContext {
            batch,
            source: &source,
            config: &config,
            project: &project,
            kernel: &kernel,
        };
        let mut out = Vec::new();
        for rule in &rules {
            let mut found = cc_rules::run_rule(*rule, pack_id, &ctx);
            out.append(&mut found);
        }
        out
    }

    fn lookup_file_id(&self, id: u64) -> Option<FileInput> {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.by_id.get(&id).copied())
    }
}

/// Extract the raw u64 salsa id from a `FileInput`.
///
/// Salsa exposes `AsId` only inside the macro's expansion; the public
/// surface gives us `Self::from_id(salsa::Id)` and `salsa::plumbing::AsId`.
/// We lean on the public `salsa::plumbing::AsId` re-export.
fn file_input_raw_id(file: FileInput) -> u64 {
    use salsa::plumbing::AsId;
    u64::from(file.as_id().as_u32())
}

/// Build a stub source table containing just the one path's bytes.
///
/// Phase 1 lift: rules will use `ctx.source` for snippet extraction;
/// because we don't carry source bytes through salsa here, the table is
/// empty (rules degrade gracefully — see `cc_rules::FileBackedSourceTable`
/// docs).
fn empty_source_table_for(_path: &Utf8Path) -> impl SourceTable {
    cc_rules::InMemorySourceTable::new()
}

/// Construct a stand-in tree-sitter tree for languages without a
/// registered frontend or for parse failures. Uses tree-sitter's
/// `Parser` against an empty grammar — but since we may have no
/// grammar at all, we use a deliberately minimal path: parse "" with
/// a leak-safe fallback.
///
/// In practice this path runs only in tests where no frontend is
/// registered; production callers always register at least one
/// frontend before issuing queries.
fn empty_tree(language: &str) -> TreeSitterTree {
    // We can't construct a `tree_sitter::Tree` without a grammar. The
    // safe fallback is to attach the rust grammar (always linked via
    // workspace deps) and parse the empty string.
    let mut parser = tree_sitter::Parser::new();
    let lang: tree_sitter::Language = tree_sitter_rust::LANGUAGE.into();
    parser
        .set_language(&lang)
        .expect("rust grammar always loadable");
    let raw = parser.parse("", None).expect("empty parse must succeed");
    // Leak the language name so we can return a `&'static str`.
    let lang_id: &'static str = Box::leak(language.to_owned().into_boxed_str());
    TreeSitterTree::new(raw, lang_id)
}
