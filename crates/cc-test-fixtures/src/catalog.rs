//! Catalog of every fixture exposed by `cc-test-fixtures`.
//!
//! The catalog is a static `&[Fixture]` table built from the embedded
//! byte slices in [`crate::languages`]. Consumers query it through
//! [`FixtureCatalog`].
//!
//! # Language coverage gaps
//!
//! - `cc.shape.no_inheritance` is **not** provided for Rust because
//!   Rust has no class inheritance; the rule has no positive form.
//! - `cc.shape.duplication`, `cc.shape.dead_code`, and
//!   `cc.shape.naming_drift` are currently Python-only — their
//!   cross-language fixtures are deferred to a later wave.
//! - `cc.error.no_action` is currently Python-only — TypeScript/Go/Rust
//!   counterparts deferred to a later wave.

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::error::FixtureError;
use crate::languages;

/// Source language of a fixture file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Language {
    /// Python source — `.py` extension.
    Python,
    /// TypeScript source — `.ts` extension.
    Typescript,
    /// Go source — `.go` extension.
    Go,
    /// Rust source — `.rs` extension.
    Rust,
}

impl Language {
    /// Return the on-disk directory name for this language.
    #[must_use]
    pub const fn dir_name(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Typescript => "typescript",
            Self::Go => "go",
            Self::Rust => "rust",
        }
    }
}

/// Whether a fixture is expected to TRIGGER a finding (Violating) or
/// NOT trigger any finding for the rule under test (Clean).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FixtureKind {
    /// Source is expected to fire the rule.
    Violating,
    /// Source is expected to be clean for the rule.
    Clean,
}

/// A single corpus entry: language + rule + violating-or-clean + bytes.
#[derive(Debug, Clone, Copy)]
pub struct Fixture {
    /// Source language of this fixture.
    pub language: Language,
    /// Stable rule id this fixture exercises (e.g. `"cc.shape.fn_length"`).
    pub rule_id: &'static str,
    /// Whether this is a violating or a clean specimen.
    pub kind: FixtureKind,
    /// Path relative to `tests/fixtures/`. Always uses forward slashes.
    pub relative_path: &'static str,
    /// Embedded source bytes (UTF-8).
    pub source: &'static [u8],
}

/// The full corpus, stored as a flat const slice.
pub(crate) const CATALOG: &[Fixture] = &[
    // ---- python / shape ----------------------------------------------------
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.fn_length",
        kind: FixtureKind::Violating,
        relative_path: "python/shape/fn_length_violating.py",
        source: languages::python::FN_LENGTH_VIOLATING,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.fn_length",
        kind: FixtureKind::Clean,
        relative_path: "python/shape/fn_length_clean.py",
        source: languages::python::FN_LENGTH_CLEAN,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.nesting_depth",
        kind: FixtureKind::Violating,
        relative_path: "python/shape/nesting_violating.py",
        source: languages::python::NESTING_VIOLATING,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.nesting_depth",
        kind: FixtureKind::Clean,
        relative_path: "python/shape/nesting_clean.py",
        source: languages::python::NESTING_CLEAN,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.param_count",
        kind: FixtureKind::Violating,
        relative_path: "python/shape/params_violating.py",
        source: languages::python::PARAMS_VIOLATING,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.param_count",
        kind: FixtureKind::Clean,
        relative_path: "python/shape/params_clean.py",
        source: languages::python::PARAMS_CLEAN,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.duplication",
        kind: FixtureKind::Violating,
        relative_path: "python/shape/duplication_violating.py",
        source: languages::python::DUPLICATION_VIOLATING,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.duplication",
        kind: FixtureKind::Clean,
        relative_path: "python/shape/duplication_clean.py",
        source: languages::python::DUPLICATION_CLEAN,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.dead_code",
        kind: FixtureKind::Violating,
        relative_path: "python/shape/dead_code_violating.py",
        source: languages::python::DEAD_CODE_VIOLATING,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.dead_code",
        kind: FixtureKind::Clean,
        relative_path: "python/shape/dead_code_clean.py",
        source: languages::python::DEAD_CODE_CLEAN,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.no_inheritance",
        kind: FixtureKind::Violating,
        relative_path: "python/shape/inheritance_violating.py",
        source: languages::python::INHERITANCE_VIOLATING,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.no_inheritance",
        kind: FixtureKind::Clean,
        relative_path: "python/shape/inheritance_clean.py",
        source: languages::python::INHERITANCE_CLEAN,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.shape.naming_drift",
        kind: FixtureKind::Violating,
        relative_path: "python/shape/naming_drift_violating.py",
        source: languages::python::NAMING_DRIFT_VIOLATING,
    },
    // ---- python / error ----------------------------------------------------
    Fixture {
        language: Language::Python,
        rule_id: "cc.error.bare",
        kind: FixtureKind::Violating,
        relative_path: "python/error/bare_violating.py",
        source: languages::python::BARE_VIOLATING,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.error.bare",
        kind: FixtureKind::Clean,
        relative_path: "python/error/bare_clean.py",
        source: languages::python::BARE_CLEAN,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.error.no_action",
        kind: FixtureKind::Violating,
        relative_path: "python/error/no_action_violating.py",
        source: languages::python::NO_ACTION_VIOLATING,
    },
    Fixture {
        language: Language::Python,
        rule_id: "cc.error.no_action",
        kind: FixtureKind::Clean,
        relative_path: "python/error/no_action_clean.py",
        source: languages::python::NO_ACTION_CLEAN,
    },
    // ---- typescript / shape ------------------------------------------------
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.shape.fn_length",
        kind: FixtureKind::Violating,
        relative_path: "typescript/shape/fn_length_violating.ts",
        source: languages::typescript::FN_LENGTH_VIOLATING,
    },
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.shape.fn_length",
        kind: FixtureKind::Clean,
        relative_path: "typescript/shape/fn_length_clean.ts",
        source: languages::typescript::FN_LENGTH_CLEAN,
    },
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.shape.nesting_depth",
        kind: FixtureKind::Violating,
        relative_path: "typescript/shape/nesting_violating.ts",
        source: languages::typescript::NESTING_VIOLATING,
    },
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.shape.nesting_depth",
        kind: FixtureKind::Clean,
        relative_path: "typescript/shape/nesting_clean.ts",
        source: languages::typescript::NESTING_CLEAN,
    },
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.shape.param_count",
        kind: FixtureKind::Violating,
        relative_path: "typescript/shape/params_violating.ts",
        source: languages::typescript::PARAMS_VIOLATING,
    },
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.shape.param_count",
        kind: FixtureKind::Clean,
        relative_path: "typescript/shape/params_clean.ts",
        source: languages::typescript::PARAMS_CLEAN,
    },
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.shape.no_inheritance",
        kind: FixtureKind::Violating,
        relative_path: "typescript/shape/inheritance_violating.ts",
        source: languages::typescript::INHERITANCE_VIOLATING,
    },
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.shape.no_inheritance",
        kind: FixtureKind::Clean,
        relative_path: "typescript/shape/inheritance_clean.ts",
        source: languages::typescript::INHERITANCE_CLEAN,
    },
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.shape.naming_drift",
        kind: FixtureKind::Violating,
        relative_path: "typescript/shape/naming_drift_violating.ts",
        source: languages::typescript::NAMING_DRIFT_VIOLATING,
    },
    // ---- typescript / error ------------------------------------------------
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.error.bare",
        kind: FixtureKind::Violating,
        relative_path: "typescript/error/bare_violating.ts",
        source: languages::typescript::BARE_VIOLATING,
    },
    Fixture {
        language: Language::Typescript,
        rule_id: "cc.error.bare",
        kind: FixtureKind::Clean,
        relative_path: "typescript/error/bare_clean.ts",
        source: languages::typescript::BARE_CLEAN,
    },
    // ---- go / shape --------------------------------------------------------
    Fixture {
        language: Language::Go,
        rule_id: "cc.shape.fn_length",
        kind: FixtureKind::Violating,
        relative_path: "go/shape/fn_length_violating.go",
        source: languages::go::FN_LENGTH_VIOLATING,
    },
    Fixture {
        language: Language::Go,
        rule_id: "cc.shape.fn_length",
        kind: FixtureKind::Clean,
        relative_path: "go/shape/fn_length_clean.go",
        source: languages::go::FN_LENGTH_CLEAN,
    },
    Fixture {
        language: Language::Go,
        rule_id: "cc.shape.nesting_depth",
        kind: FixtureKind::Violating,
        relative_path: "go/shape/nesting_violating.go",
        source: languages::go::NESTING_VIOLATING,
    },
    Fixture {
        language: Language::Go,
        rule_id: "cc.shape.nesting_depth",
        kind: FixtureKind::Clean,
        relative_path: "go/shape/nesting_clean.go",
        source: languages::go::NESTING_CLEAN,
    },
    Fixture {
        language: Language::Go,
        rule_id: "cc.shape.param_count",
        kind: FixtureKind::Violating,
        relative_path: "go/shape/params_violating.go",
        source: languages::go::PARAMS_VIOLATING,
    },
    Fixture {
        language: Language::Go,
        rule_id: "cc.shape.param_count",
        kind: FixtureKind::Clean,
        relative_path: "go/shape/params_clean.go",
        source: languages::go::PARAMS_CLEAN,
    },
    Fixture {
        language: Language::Go,
        rule_id: "cc.shape.dead_code",
        kind: FixtureKind::Violating,
        relative_path: "go/shape/dead_code_violating.go",
        source: languages::go::DEAD_CODE_VIOLATING,
    },
    Fixture {
        language: Language::Go,
        rule_id: "cc.shape.dead_code",
        kind: FixtureKind::Clean,
        relative_path: "go/shape/dead_code_clean.go",
        source: languages::go::DEAD_CODE_CLEAN,
    },
    // ---- go / error --------------------------------------------------------
    Fixture {
        language: Language::Go,
        rule_id: "cc.error.bare",
        kind: FixtureKind::Violating,
        relative_path: "go/error/bare_violating.go",
        source: languages::go::BARE_VIOLATING,
    },
    Fixture {
        language: Language::Go,
        rule_id: "cc.error.bare",
        kind: FixtureKind::Clean,
        relative_path: "go/error/bare_clean.go",
        source: languages::go::BARE_CLEAN,
    },
    // ---- rust / shape ------------------------------------------------------
    Fixture {
        language: Language::Rust,
        rule_id: "cc.shape.fn_length",
        kind: FixtureKind::Violating,
        relative_path: "rust/shape/fn_length_violating.rs",
        source: languages::rust::FN_LENGTH_VIOLATING,
    },
    Fixture {
        language: Language::Rust,
        rule_id: "cc.shape.fn_length",
        kind: FixtureKind::Clean,
        relative_path: "rust/shape/fn_length_clean.rs",
        source: languages::rust::FN_LENGTH_CLEAN,
    },
    Fixture {
        language: Language::Rust,
        rule_id: "cc.shape.nesting_depth",
        kind: FixtureKind::Violating,
        relative_path: "rust/shape/nesting_violating.rs",
        source: languages::rust::NESTING_VIOLATING,
    },
    Fixture {
        language: Language::Rust,
        rule_id: "cc.shape.nesting_depth",
        kind: FixtureKind::Clean,
        relative_path: "rust/shape/nesting_clean.rs",
        source: languages::rust::NESTING_CLEAN,
    },
    Fixture {
        language: Language::Rust,
        rule_id: "cc.shape.param_count",
        kind: FixtureKind::Violating,
        relative_path: "rust/shape/params_violating.rs",
        source: languages::rust::PARAMS_VIOLATING,
    },
    Fixture {
        language: Language::Rust,
        rule_id: "cc.shape.param_count",
        kind: FixtureKind::Clean,
        relative_path: "rust/shape/params_clean.rs",
        source: languages::rust::PARAMS_CLEAN,
    },
    Fixture {
        language: Language::Rust,
        rule_id: "cc.shape.dead_code",
        kind: FixtureKind::Violating,
        relative_path: "rust/shape/dead_code_violating.rs",
        source: languages::rust::DEAD_CODE_VIOLATING,
    },
    Fixture {
        language: Language::Rust,
        rule_id: "cc.shape.dead_code",
        kind: FixtureKind::Clean,
        relative_path: "rust/shape/dead_code_clean.rs",
        source: languages::rust::DEAD_CODE_CLEAN,
    },
    // ---- rust / error ------------------------------------------------------
    Fixture {
        language: Language::Rust,
        rule_id: "cc.error.bare",
        kind: FixtureKind::Violating,
        relative_path: "rust/error/bare_violating.rs",
        source: languages::rust::BARE_VIOLATING,
    },
    Fixture {
        language: Language::Rust,
        rule_id: "cc.error.bare",
        kind: FixtureKind::Clean,
        relative_path: "rust/error/bare_clean.rs",
        source: languages::rust::BARE_CLEAN,
    },
];

/// Read-only entry point for browsing the static fixture corpus.
///
/// `FixtureCatalog` carries no state — every method is a static
/// accessor over the embedded `CATALOG` table.
#[derive(Debug, Clone, Copy, Default)]
pub struct FixtureCatalog;

impl FixtureCatalog {
    /// Return every fixture in the corpus, in declaration order.
    #[must_use]
    pub const fn all() -> &'static [Fixture] {
        CATALOG
    }

    /// Iterate over fixtures whose `rule_id` matches exactly.
    pub fn by_rule(rule_id: &str) -> impl Iterator<Item = &'static Fixture> + '_ {
        CATALOG.iter().filter(move |f| f.rule_id == rule_id)
    }

    /// Iterate over fixtures whose `language` matches exactly.
    pub fn by_language(lang: Language) -> impl Iterator<Item = &'static Fixture> {
        CATALOG.iter().filter(move |f| f.language == lang)
    }

    /// Iterate over fixtures matching both a `rule_id` and a `kind`.
    pub fn for_rule_kind(
        rule_id: &str,
        kind: FixtureKind,
    ) -> impl Iterator<Item = &'static Fixture> + '_ {
        CATALOG
            .iter()
            .filter(move |f| f.rule_id == rule_id && f.kind == kind)
    }

    /// Look up the unique fixture for a `(language, rule_id, kind)` triple.
    ///
    /// Returns `None` if no fixture matches — for example, asking for
    /// `(Language::Rust, "cc.shape.no_inheritance", _)` (Rust gap).
    #[must_use]
    pub fn lookup(
        language: Language,
        rule_id: &str,
        kind: FixtureKind,
    ) -> Option<&'static Fixture> {
        CATALOG
            .iter()
            .find(|f| f.language == language && f.rule_id == rule_id && f.kind == kind)
    }
}

/// Materialise the given fixtures under `root`, preserving the
/// `relative_path` layout (`<root>/<language>/<rule>/<file>`).
///
/// Parent directories are created on demand. Existing files are
/// overwritten — callers that want a clean slate should pass an empty
/// directory.
///
/// # Errors
///
/// Returns [`FixtureError::Mkdir`] if a parent directory cannot be
/// created, or [`FixtureError::Write`] if the file cannot be written.
pub fn write_to_tempdir(fixtures: &[&Fixture], root: &Utf8Path) -> Result<(), FixtureError> {
    for fixture in fixtures {
        let target = build_target_path(root, fixture.relative_path);
        ensure_parent(&target)?;
        std::fs::write(&target, fixture.source).map_err(|source| FixtureError::Write {
            path: target,
            source,
        })?;
    }
    Ok(())
}

fn build_target_path(root: &Utf8Path, relative: &str) -> Utf8PathBuf {
    let mut path = root.to_path_buf();
    for segment in relative.split('/') {
        path.push(segment);
    }
    path
}

fn ensure_parent(target: &Utf8Path) -> Result<(), FixtureError> {
    let Some(parent) = target.parent() else {
        return Ok(());
    };
    if parent.as_str().is_empty() || parent.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|source| FixtureError::Mkdir {
        path: parent.to_path_buf(),
        source,
    })
}
