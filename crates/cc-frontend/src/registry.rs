//! Language registry + `FrontendCore` glue used by the kernel.
//!
//! `LanguageRegistry` is a small trait-object map keyed by language name and
//! by file extension. `FrontendCore` adds the disk-read + parse + lift
//! orchestration the kernel needs.

use std::collections::HashMap;

use camino::Utf8Path;
use cc_cpg::{CpgWriteBatch, NodeId};

use crate::errors::FrontendError;
use crate::frontend::{FileId, LanguageFrontend};

/// Trait-object registry of installed [`LanguageFrontend`]s.
///
/// Lookups are by file-extension (`"py"`, `"ts"`, ...) or by language name
/// (`"python"`, `"typescript"`, ...). One frontend may register multiple
/// extensions — registry stores the same trait object behind each.
#[derive(Default)]
pub struct LanguageRegistry {
    by_language: HashMap<&'static str, usize>,
    by_extension: HashMap<&'static str, usize>,
    frontends: Vec<Box<dyn LanguageFrontend>>,
}

impl LanguageRegistry {
    /// Empty registry — no languages installed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a frontend. Each of its `file_extensions()` becomes a
    /// lookup key; the language name becomes another.
    ///
    /// Re-registering the same name or extension overwrites the previous
    /// entry. We intentionally don't return an error — the registry exists
    /// to be configured at boot, and silent overwrite matches the way
    /// kernel config layers compose.
    pub fn register(&mut self, frontend: Box<dyn LanguageFrontend>) {
        let name = frontend.language_name();
        let extensions = frontend.file_extensions();
        let idx = self.frontends.len();
        for ext in extensions {
            self.by_extension.insert(*ext, idx);
        }
        self.by_language.insert(name, idx);
        self.frontends.push(frontend);
    }

    /// Look up a frontend by file extension (without leading `.`).
    #[must_use]
    pub fn for_extension(&self, ext: &str) -> Option<&dyn LanguageFrontend> {
        self.by_extension
            .get(ext)
            .and_then(|i| self.frontends.get(*i))
            .map(AsRef::as_ref)
    }

    /// Look up a frontend by language name.
    #[must_use]
    pub fn for_language(&self, name: &str) -> Option<&dyn LanguageFrontend> {
        self.by_language
            .get(name)
            .and_then(|i| self.frontends.get(*i))
            .map(AsRef::as_ref)
    }

    /// Snapshot of every installed language name. Useful for diagnostics.
    #[must_use]
    pub fn registered_languages(&self) -> Vec<&'static str> {
        self.by_language.keys().copied().collect()
    }
}

/// Top-level orchestrator wired into `cc-kernel`.
///
/// Owns the [`LanguageRegistry`]; provides one entry-point —
/// [`FrontendCore::parse_and_lift`] — which the kernel calls per file.
pub struct FrontendCore {
    registry: LanguageRegistry,
}

impl FrontendCore {
    /// Wrap an existing registry.
    #[must_use]
    pub const fn new(registry: LanguageRegistry) -> Self {
        Self { registry }
    }

    /// Borrow the underlying registry (read-only).
    #[must_use]
    pub const fn registry(&self) -> &LanguageRegistry {
        &self.registry
    }

    /// Read `file`, parse it, lift it into `store`, and return the file's
    /// root [`NodeId`].
    ///
    /// # Errors
    ///
    /// Returns [`FrontendError`] if the extension isn't registered, the
    /// file can't be read, parsing fails, or a fatal lift error occurs.
    /// Non-fatal lift errors are absorbed by the frontend (it inserts
    /// `Unresolved` markers and continues).
    pub fn parse_and_lift(
        &self,
        file: &Utf8Path,
        store: &mut CpgWriteBatch,
        file_id: FileId,
    ) -> Result<NodeId, FrontendError> {
        let frontend = self.frontend_for(file)?;
        let source = read_source(file)?;
        let tree = frontend.parse(&source)?;
        let root = frontend.lift(&tree, &source, store, file_id)?;
        // Post-passes: REFERENCES (name resolver) then CG_CALLS (call
        // resolver). Both run against the same batch the lift just
        // populated; failures here are treated as soft warnings — the
        // batch still contains every AST node + DECLARES edge, so
        // downstream rules that don't need call resolution stay correct.
        if let Err(err) = frontend.resolve_names(store) {
            tracing::warn!(
                target: "cc_frontend::registry",
                language = frontend.language_name(),
                path = file.as_str(),
                error = %err,
                "name resolver returned a diagnostic; continuing"
            );
        }
        if let Err(err) = frontend.resolve_calls(store) {
            tracing::warn!(
                target: "cc_frontend::registry",
                language = frontend.language_name(),
                path = file.as_str(),
                error = %err,
                "call resolver returned a diagnostic; continuing"
            );
        }
        Ok(root)
    }

    /// Resolve which frontend owns this file, or return a kernel-actionable
    /// error.
    fn frontend_for(&self, file: &Utf8Path) -> Result<&dyn LanguageFrontend, FrontendError> {
        let ext = file.extension().unwrap_or_default();
        self.registry
            .for_extension(ext)
            .ok_or_else(|| FrontendError::UnknownExtension {
                extension: ext.to_owned(),
                path: file.as_str().to_owned(),
            })
    }
}

/// Read a UTF-8 source file, mapping I/O errors into the public error type.
fn read_source(file: &Utf8Path) -> Result<String, FrontendError> {
    std::fs::read_to_string(file.as_std_path()).map_err(|e| FrontendError::Io {
        path: file.as_str().to_owned(),
        source_msg: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::{LiftError, ParseError};
    use crate::TreeSitterTree;

    struct MockFrontend;

    impl LanguageFrontend for MockFrontend {
        fn language_name(&self) -> &'static str {
            "mocklang"
        }
        fn file_extensions(&self) -> &'static [&'static str] {
            &["mk", "mock"]
        }
        fn parse(&self, _source: &str) -> Result<TreeSitterTree, ParseError> {
            unimplemented!("mock frontend used for registry lookup tests only")
        }
        fn lift(
            &self,
            _tree: &TreeSitterTree,
            _source: &str,
            _store: &mut CpgWriteBatch,
            _file_id: FileId,
        ) -> Result<NodeId, LiftError> {
            unimplemented!("mock frontend used for registry lookup tests only")
        }
    }

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = LanguageRegistry::new();
        reg.register(Box::new(MockFrontend));

        let by_ext = reg.for_extension("mk").expect("ext lookup");
        assert_eq!(by_ext.language_name(), "mocklang");

        let by_other_ext = reg.for_extension("mock").expect("alt ext lookup");
        assert_eq!(by_other_ext.language_name(), "mocklang");

        let by_name = reg.for_language("mocklang").expect("lang lookup");
        assert_eq!(by_name.file_extensions(), &["mk", "mock"]);

        assert!(reg.for_extension("xyz").is_none());
        let langs = reg.registered_languages();
        assert_eq!(langs, vec!["mocklang"]);
    }
}
