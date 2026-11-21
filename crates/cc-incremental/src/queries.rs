//! Tracked Salsa queries — the cached compute pipeline.
//!
//! Every query in this module is a free `#[salsa::tracked(no_eq)]`
//! function. They
//! key on [`crate::FileInput`] / [`crate::RepoInput`]; salsa caches the
//! return value across invocations until a transitively-depended-on input
//! changes (i.e., until [`crate::CcDatabase::update_file`] is called with
//! new content for one of the input files).
//!
//! # Why newtype wrappers
//!
//! [`tree_sitter::Tree`], [`cc_cpg::CpgWriteBatch`], and `Vec<Finding>` are
//! foreign types we cannot impl [`salsa::Update`] on directly (orphan
//! rule). The `wrappers` submodule wraps each in a thin newtype that
//! carries a manual `Update` impl with **always-replace-on-new-revision**
//! semantics — appropriate because these are pure computed outputs of a
//! tracked function (salsa hands us a freshly-produced value; the previous
//! one is dropped).
//!
//! Salsa's `#[salsa::tracked]` macro emits associated items + a marker
//! struct without doc strings; the module-scope `allow(missing_docs)`
//! below keeps the lint silent without weakening it elsewhere.
#![allow(missing_docs)]

use std::sync::Arc;

use crate::db::CcDb;
use crate::inputs::{FileInput, RepoInput};

pub use wrappers::{CachedCpg, CachedFindings, CachedTree};

/// Parse a file's content with the appropriate frontend.
///
/// Cached on `FileInput.content_hash`; same hash -> same `Arc`. If the
/// file's language is unknown, returns an empty placeholder tree (the
/// kernel surfaces unknown-language warnings elsewhere).
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
#[salsa::tracked(no_eq)]
pub fn parsed_tree(db: &dyn CcDb, file: FileInput) -> CachedTree {
    let (content, language) = file_inputs(db, file);
    log_recompute("parsed_tree", language, Some(content.len()));
    let tree = db.parse_with_frontend(language, content);
    CachedTree(Arc::new(tree))
}

/// Lift a parsed tree into a CPG write batch.
///
/// Cached on `FileInput`; transitively invalidated when `parsed_tree`
/// invalidates (i.e. when `content_hash` changes).
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
#[salsa::tracked(no_eq)]
pub fn cpg_root(db: &dyn CcDb, file: FileInput) -> CachedCpg {
    let tree = parsed_tree(db, file);
    let (content, language) = file_inputs(db, file);
    log_recompute("cpg_root", language, None);
    let batch = db.lift_with_frontend(language, &tree.0, content, file);
    CachedCpg(Arc::new(batch))
}

/// Borrow `(content, language)` from a [`FileInput`] in one place.
/// Centralising the field accesses lets the tracked queries above read
/// like specifications instead of plumbing.
fn file_inputs(db: &dyn CcDb, file: FileInput) -> (&String, &String) {
    (file.content(db), file.language(db))
}

/// Emit the standard `recompute` debug log for a tracked query stage.
/// `bytes_hint` is only attached when the caller has it cheaply (i.e.
/// `parsed_tree` already holds the content slice; `cpg_root` doesn't
/// need it).
fn log_recompute(stage: &'static str, language: &str, bytes_hint: Option<usize>) {
    if let Some(bytes) = bytes_hint {
        tracing::debug!(
            target: "cc_incremental::query",
            stage,
            lang = %language,
            bytes,
            "tracked recompute"
        );
    } else {
        tracing::debug!(
            target: "cc_incremental::query",
            stage,
            lang = %language,
            "tracked recompute"
        );
    }
}

/// Run all registered rules against a file's CPG batch.
///
/// Cached per file. Note: when a [`crate::RuleInput`] changes (pack
/// upgrade), invalidating findings requires the caller to rebump the
/// rule input, which in turn invalidates this query via the
/// `db.run_rules_with_inputs` read.
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
#[salsa::tracked(no_eq)]
pub fn findings_for(db: &dyn CcDb, file: FileInput) -> CachedFindings {
    let cpg = cpg_root(db, file);
    let path = file.path(db).0.clone();
    tracing::debug!(
        target: "cc_incremental::query",
        path = %path,
        "findings_for recompute"
    );
    let findings = db.run_rules_with_inputs(&cpg.0, &path);
    CachedFindings(Arc::new(findings))
}

/// Per-file health score, in `[0.0, 1.0]`. 1.0 = clean.
///
/// Computed from `findings_for(file)`. A file with zero findings scores
/// 1.0; severity- and confidence-weighted deductions reduce it.
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
#[salsa::tracked(no_eq)]
pub fn health_score_for_file(db: &dyn CcDb, file: FileInput) -> f64 {
    let findings = findings_for(db, file);
    let path = file.path(db).0.clone();
    tracing::debug!(
        target: "cc_incremental::query",
        path = %path,
        n_findings = findings.0.len(),
        "health_score_for_file recompute"
    );
    score_from_findings(&findings.0)
}

/// Repo-wide health score — weighted average of per-file scores.
///
/// Recomputed only when at least one file's per-file score changes (or
/// when `RepoInput.file_ids` changes). Files in `file_ids` whose
/// `FileInput` cannot be resolved (stale id) are skipped with a debug log.
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
#[salsa::tracked(no_eq)]
pub fn repo_health_score(db: &dyn CcDb, repo: RepoInput) -> f64 {
    let file_ids = repo.file_ids(db);
    tracing::debug!(
        target: "cc_incremental::query",
        n_files = file_ids.len(),
        "repo_health_score recompute"
    );
    if file_ids.is_empty() {
        return 1.0;
    }
    let mut sum = 0.0_f64;
    let mut counted = 0_usize;
    for &id in file_ids {
        if let Some(file) = db.lookup_file_id(id) {
            sum += health_score_for_file(db, file);
            counted += 1;
        }
    }
    if counted == 0 {
        1.0
    } else {
        // Acceptable precision loss: `counted` is the number of files
        // and a 100k-LOC repo has ~10k files — well below 2^52.
        #[allow(clippy::cast_precision_loss)]
        let denom = counted as f64;
        sum / denom
    }
}

/// Severity-weighted score derivation.
///
/// Stand-in algorithm for Phase 1: each finding deducts a fixed amount
/// scaled by severity. The real `cc-score` crate replaces this in W3.T5.
fn score_from_findings(findings: &[cc_finding::Finding]) -> f64 {
    use cc_finding::Severity;
    let mut score: f64 = 1.0;
    for f in findings {
        let weight = match f.severity {
            Severity::Blocker => 0.10,
            Severity::Required => 0.03,
            Severity::Nit => 0.005,
        };
        score -= weight * f64::from(f.confidence.get());
        if score <= 0.0 {
            return 0.0;
        }
    }
    score
}

mod wrappers {
    //! Newtype wrappers that satisfy [`salsa::Update`] for foreign types.
    //!
    //! Semantics: on every new revision the cached value is replaced
    //! wholesale. This is sound because tracked-function outputs are
    //! produced by-value from the function body; the salsa runtime hands
    //! us a fresh `Self` and the old one is dropped by the standard
    //! `*old_pointer = new_value` write.

    use std::sync::Arc;

    use cc_cpg::CpgWriteBatch;
    use cc_finding::Finding;
    use cc_frontend::TreeSitterTree;

    /// Cached parsed tree, keyed implicitly by `FileInput.content_hash`.
    #[derive(Debug, Clone)]
    pub struct CachedTree(pub Arc<TreeSitterTree>);

    /// Cached CPG write batch produced by lifting the parsed tree.
    #[derive(Debug, Clone)]
    pub struct CachedCpg(pub Arc<CpgWriteBatch>);

    /// Cached per-file findings list.
    #[derive(Debug, Clone)]
    pub struct CachedFindings(pub Arc<Vec<Finding>>);

    // SAFETY: All three wrappers carry an `Arc<T>` over a foreign type.
    // We don't compare T's contents (Eq isn't available); instead we
    // detect identity via `Arc::ptr_eq` for the no-op fast path and
    // otherwise replace wholesale. Replacement is sound because the
    // salsa runtime calls this only when handing us a freshly-produced
    // value; no aliased `&T` outside the database can exist (Update's
    // safety doc forbids `&'db T` references).
    impl_salsa_update_arc_ptr_eq!(CachedTree);
    impl_salsa_update_arc_ptr_eq!(CachedCpg);
    impl_salsa_update_arc_ptr_eq!(CachedFindings);
}
