//! [`Analyser`] — wraps [`cc_incremental::CcDatabase`] for the LSP daemon.
//!
//! Responsibilities:
//!
//! 1. Own a salsa-backed incremental database keyed on file content hash
//!    so consecutive `did_change` events for unchanged regions reuse the
//!    cached parse + lift (the editor sends a full document on every
//!    change under [`tower_lsp::lsp_types::TextDocumentSyncKind::FULL`]
//!    — the cache hit on the *content* shortcut still helps when the
//!    user pauses).
//! 2. Register every Phase-1 frontend (Python, TS, Go, Rust) at construction
//!    so the daemon supports every language the kernel does.
//! 3. Expose a single [`Analyser::analyse`] entry point that the
//!    [`crate::CcLspServer`] can call from `did_open` / `did_change` /
//!    `did_save` handlers without touching salsa types directly.
//!
//! # Why we don't use [`cc_incremental::CcDatabase::findings_for`]
//!
//! The salsa `findings_for` query runs every rule against an
//! [`cc_rules::InMemorySourceTable`] that the database keeps **empty**
//! (see `cc_incremental::db::empty_source_table_for`). Several Tier-0
//! rules (`R-FN-LEN`, `R-FILE-LEN`) consult `ctx.source` to compute
//! logical-LOC counts and silently skip when the bytes are missing —
//! which is the right default for a CPG-only kernel run, but wrong for
//! an LSP server that has the buffer text in hand.
//!
//! We therefore use the database for parse-and-lift caching (`cpg_root`)
//! only, then run rules ourselves with a per-call
//! [`cc_rules::InMemorySourceTable`] populated from the editor buffer.
//!
//! # Threading
//!
//! [`Analyser`] is held behind a [`tokio::sync::Mutex`] in the server
//! because [`cc_incremental::CcDatabase`] requires `&mut self` for input
//! updates. The lock is held only while the (fast) salsa update + query
//! pass runs; in practice this serialises analysis but does NOT serialise
//! editor protocol traffic (which `tower-lsp` runs on a separate task).

use std::sync::Arc;

use camino::Utf8PathBuf;
use cc_finding::Finding;
use cc_frontend::{FrontendCore, LanguageRegistry};
use cc_frontend_go::GoFrontend;
use cc_frontend_python::PythonFrontend;
use cc_frontend_rust::RustFrontend;
use cc_frontend_typescript::TypescriptFrontend;
use cc_incremental::{CcDatabase, FileInput};
use cc_rules::{
    run_rule, InMemorySourceTable, KernelMeta, ProjectFingerprint, Rule, RuleContext, RulePack,
};
use cc_rules_tier0::BuiltinTier0Pack;
use tower_lsp::lsp_types::Url;

use crate::error::{LspError, LspResult};

/// Salsa-backed analyser — the bridge between the LSP server and the
/// rest of the kernel.
pub struct Analyser {
    db: CcDatabase,
    rules: Vec<&'static dyn Rule>,
    pack_id: &'static str,
    project: ProjectFingerprint,
}

impl Analyser {
    /// Construct an analyser with every Phase-1 frontend and the Tier-0
    /// rule pack registered.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns [`LspResult`] so the constructor
    /// stays future-compatible with config-driven rule selection.
    pub fn new() -> LspResult<Self> {
        let mut db = CcDatabase::new();
        db.register_frontends(Arc::new(build_frontend_core()));
        let pack = BuiltinTier0Pack;
        let rules: Vec<&'static dyn Rule> = pack.rules().to_vec();
        // We still register the rules into the salsa db so the
        // `findings_for` cache stays warm if a future caller chooses to
        // use it — even though `analyse()` runs rules directly.
        db.register_rules(BuiltinTier0Pack::PACK_ID, rules.clone());
        let _ = db.add_rule_input(BuiltinTier0Pack::PACK_ID, BuiltinTier0Pack::PACK_SEMVER);
        Ok(Self {
            db,
            rules,
            pack_id: BuiltinTier0Pack::PACK_ID,
            project: ProjectFingerprint::empty(),
        })
    }

    /// Analyse one open document.
    ///
    /// Routes the URI to a repo-relative path, registers / updates the
    /// document in the salsa db (cache-hits the parse + lift on
    /// content-stable revisions), then runs the registered rules with a
    /// per-call [`InMemorySourceTable`] populated from `text`.
    ///
    /// # Errors
    ///
    /// - [`LspError::InvalidUri`] when the URI cannot be turned into a
    ///   `file:` path.
    /// - [`LspError::UnsupportedLanguage`] when the path's extension
    ///   maps to no registered frontend.
    pub fn analyse(&mut self, uri: &Url, text: &str) -> LspResult<Vec<Finding>> {
        let path = uri_to_path(uri)?;
        let language = language_for_path(&path).ok_or_else(|| LspError::UnsupportedLanguage {
            extension: path.extension().unwrap_or_default().to_owned(),
            uri: uri.to_string(),
        })?;
        let file = self.upsert_file(path.clone(), text, language);
        let cpg = self.db.cpg_root(file).0;
        // The frontend lift does NOT populate the `path` string prop on
        // `File` nodes — that is the kernel's responsibility per the
        // integration contract. We replicate the kernel's JSON-roundtrip
        // patch (`cc_kernel::runner::patch_file_path`) so probes that
        // walk to the enclosing file and read `path` (R-FN-LEN, R-FILE-LEN,
        // …) see the right value.
        let patched = patch_file_path(cpg.as_ref(), &path);
        Ok(self.run_rules_with_text(&path, text, &patched))
    }

    /// Run every registered rule against `batch`, providing source bytes
    /// via a freshly-built in-memory source table so byte-window probes
    /// (R-FN-LEN, R-FILE-LEN, ...) see real text.
    fn run_rules_with_text(
        &self,
        path: &camino::Utf8Path,
        text: &str,
        batch: &cc_cpg::CpgWriteBatch,
    ) -> Vec<Finding> {
        let source = InMemorySourceTable::new();
        source.insert(path.to_path_buf(), text.as_bytes().to_vec());
        let kernel = KernelMeta::now();
        let config = cc_config::RuleConfig::default();
        let ctx = RuleContext {
            batch,
            source: &source,
            config: &config,
            project: &self.project,
            kernel: &kernel,
        };
        let mut findings: Vec<Finding> = Vec::new();
        for rule in &self.rules {
            let mut produced = run_rule(*rule, self.pack_id, &ctx);
            findings.append(&mut produced);
        }
        findings
    }

    /// Register a fresh document or update an existing one in place.
    fn upsert_file(&mut self, path: Utf8PathBuf, text: &str, language: &str) -> FileInput {
        if let Some(existing) = self.db.lookup_path(&path) {
            // Existing FileInput: salsa setter path — preserves the id
            // and only invalidates queries when the content hash differs.
            let _changed = self.db.update_file(existing, text.to_owned());
            existing
        } else {
            self.db.add_file(path, text.to_owned(), language.to_owned())
        }
    }
}

/// Build the [`FrontendCore`] holding every Phase-1 frontend.
///
/// The kernel registers the same set in `cc_kernel::language` —
/// `cc-lsp` carries its own copy because the kernel-side dispatch does
/// not flow through [`FrontendCore`] / [`LanguageRegistry`] (yet).
fn build_frontend_core() -> FrontendCore {
    let mut registry = LanguageRegistry::new();
    registry.register(Box::new(PythonFrontend::new()));
    registry.register(Box::new(TypescriptFrontend::new()));
    registry.register(Box::new(GoFrontend::new()));
    registry.register(Box::new(RustFrontend::new()));
    FrontendCore::new(registry)
}

/// Translate an LSP `file:` URI into a UTF-8 absolute path.
///
/// Non-`file:` schemes (`untitled:`, `git:`, `vscode-vfs:`) are not yet
/// supported — Phase 1 only analyses on-disk source.
fn uri_to_path(uri: &Url) -> LspResult<Utf8PathBuf> {
    if uri.scheme() != "file" {
        return Err(LspError::InvalidUri {
            uri: uri.to_string(),
            reason: "expected scheme 'file:' (untitled / virtual schemes not supported in Phase 1)",
        });
    }
    let raw = uri.to_file_path().map_err(|()| LspError::InvalidUri {
        uri: uri.to_string(),
        reason: "URI does not resolve to an OS path",
    })?;
    Utf8PathBuf::from_path_buf(raw).map_err(|bad| LspError::InvalidUri {
        uri: bad.to_string_lossy().into_owned(),
        reason: "path is not valid UTF-8",
    })
}

/// Inject the `path` string prop onto every `File` node in `batch`.
///
/// Phase-1 frontends emit `File` nodes with `language` / `file_id` /
/// `range` but not `path` — the kernel patches them after lift. Tier-0
/// rules walk to the enclosing `File` and read `path` to fetch source
/// bytes, so we replicate the kernel's JSON-roundtrip patch here.
///
/// The cost is one allocation per analysed file. Acceptable for an LSP
/// daemon where parse + lift dominates the per-keystroke budget.
/// TODO: replace with a direct setter once `cc-cpg` exposes one.
fn patch_file_path(
    batch: &cc_cpg::CpgWriteBatch,
    path: &camino::Utf8Path,
) -> cc_cpg::CpgWriteBatch {
    let Ok(mut value) = serde_json::to_value(batch) else {
        return batch.clone();
    };
    if let Some(nodes) = value.get_mut("nodes").and_then(|v| v.as_array_mut()) {
        for node in nodes {
            inject_path_into_file(node, path);
        }
    }
    serde_json::from_value(value).unwrap_or_else(|_| batch.clone())
}

/// If `node` is a `File`-kind JSON object, set its `path` prop.
fn inject_path_into_file(node: &mut serde_json::Value, path: &camino::Utf8Path) {
    let kind_is_file = node
        .get("kind")
        .and_then(|k| k.as_str())
        .is_some_and(|s| s == "File");
    if !kind_is_file {
        return;
    }
    let Some(props) = node.get_mut("props").and_then(|v| v.as_object_mut()) else {
        return;
    };
    let entry = serde_json::json!({ "String": path.as_str() });
    props.insert("path".to_owned(), entry);
}

/// Resolve a path's extension to a language name registered with
/// [`build_frontend_core`].
fn language_for_path(path: &camino::Utf8Path) -> Option<&'static str> {
    let ext = path.extension()?.to_ascii_lowercase();
    match ext.as_str() {
        "py" | "pyi" => Some("python"),
        "ts" | "mts" | "cts" | "js" | "mjs" | "cjs" | "tsx" | "jsx" => Some("typescript"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `file:` URI that `Url::to_file_path` will accept on every
    /// platform — Windows demands a drive-letter path; POSIX accepts any
    /// absolute path. We use [`std::env::temp_dir`] which always yields
    /// a syntactically correct absolute path for the running OS.
    fn temp_uri(filename: &str) -> Url {
        let path = std::env::temp_dir().join(filename);
        Url::from_file_path(&path).expect("temp_dir produces a valid file URL")
    }

    /// Build a Python body big enough to clear the R-FN-LEN threshold
    /// (50 LOC). Avoids `(0..n).map(format!).collect::<String>()` so the
    /// `clippy::format_collect` lint stays quiet.
    fn build_long_python_body(line_count: usize) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(line_count * 16);
        for i in 0..line_count {
            // Writes to `String` are infallible; ignore the Result.
            let _ = writeln!(out, "    x_{i} = {i}");
        }
        out
    }

    #[test]
    fn analyser_constructs() {
        let _analyser = Analyser::new().expect("Analyser::new succeeds");
    }

    #[test]
    fn language_for_path_routes_known_extensions() {
        let p = Utf8PathBuf::from("a/b/c.py");
        assert_eq!(language_for_path(&p), Some("python"));
        let p = Utf8PathBuf::from("foo.tsx");
        assert_eq!(language_for_path(&p), Some("typescript"));
        let p = Utf8PathBuf::from("foo.go");
        assert_eq!(language_for_path(&p), Some("go"));
        let p = Utf8PathBuf::from("foo.rs");
        assert_eq!(language_for_path(&p), Some("rust"));
        let p = Utf8PathBuf::from("foo.unknown");
        assert_eq!(language_for_path(&p), None);
    }

    #[test]
    fn analyse_unknown_extension_yields_unsupported_language_error() {
        let mut analyser = Analyser::new().expect("ctor");
        let uri = temp_uri("cc_lsp_test_unknown.unknown");
        let err = analyser
            .analyse(&uri, "anything")
            .expect_err("unknown ext rejected");
        assert!(matches!(err, LspError::UnsupportedLanguage { .. }));
    }

    #[test]
    fn analyse_short_python_does_not_flag_fn_length() {
        let mut analyser = Analyser::new().expect("ctor");
        let uri = temp_uri("cc_lsp_test_short.py");
        // 2-LOC function: well below the 50-LOC R-FN-LEN ceiling. Other
        // Tier-0 probes (R-TYPE-COVERAGE, etc.) may still fire on a
        // bare `def f():` shape — that's a property of those rules and
        // is verified in their own crate's tests; here we only assert
        // that R-FN-LEN does NOT fire on short input.
        let findings = analyser
            .analyse(&uri, "def f():\n    return 1\n")
            .expect("analyse");
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id.as_ref() != "cc.shape.fn_length"),
            "did not expect R-FN-LEN; got rule_ids = {:?}",
            findings
                .iter()
                .map(|f| f.rule_id.as_ref())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn analyse_long_python_function_triggers_fn_length() {
        let mut analyser = Analyser::new().expect("ctor");
        let uri = temp_uri("cc_lsp_test_long.py");
        let body = build_long_python_body(120);
        let source = format!("def long_function():\n{body}    return x_0\n");
        let findings = analyser.analyse(&uri, &source).expect("analyse");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_ref() == "cc.shape.fn_length"),
            "expected R-FN-LEN; got rule_ids = {:?}",
            findings
                .iter()
                .map(|f| f.rule_id.as_ref())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn analyse_change_then_clean_clears_findings() {
        let mut analyser = Analyser::new().expect("ctor");
        let uri = temp_uri("cc_lsp_test_toggle.py");
        let body = build_long_python_body(120);
        let dirty = format!("def long_function():\n{body}    return x_0\n");
        let dirty_findings = analyser.analyse(&uri, &dirty).expect("dirty");
        assert!(
            dirty_findings
                .iter()
                .any(|f| f.rule_id.as_ref() == "cc.shape.fn_length"),
            "expected R-FN-LEN on dirty input"
        );
        let clean_findings = analyser
            .analyse(&uri, "def f():\n    return 1\n")
            .expect("clean");
        assert!(
            clean_findings
                .iter()
                .all(|f| f.rule_id.as_ref() != "cc.shape.fn_length"),
            "did not expect R-FN-LEN after edit; got: {:?}",
            clean_findings
                .iter()
                .map(|f| f.rule_id.as_ref())
                .collect::<Vec<_>>()
        );
    }
}
