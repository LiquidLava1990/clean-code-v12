//! Repo file walker — `.gitignore`-aware, glob-scoped, size-capped.
//!
//! `walk_repo` produces an iterator of repo-relative `Utf8PathBuf`
//! candidates. The kernel then filters out unsupported extensions in a
//! second pass; this keeps the walker single-purpose and testable.

use camino::{Utf8Path, Utf8PathBuf};
use cc_config::{path_scope::build_globset, Config};
use globset::GlobSet;
use ignore::WalkBuilder;

use crate::error::{KernelError, KernelResult};

/// Default per-file size cap. Files larger than this are skipped with a
/// `tracing::warn!`. 5 MiB is high enough to admit any sane source file
/// and low enough to keep the parser memory-bound.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Result of [`walk_repo`].
///
/// `included` holds files that survived ignore + scope filters and are
/// candidates for parse + lift. `skipped` counts files that were walked
/// but filtered out (size cap, scope exclude, oversize, etc.) so the
/// kernel can surface `files_skipped` in its run report.
#[derive(Debug, Default)]
pub struct WalkOutcome {
    /// Repo-relative paths surviving every filter.
    pub included: Vec<Utf8PathBuf>,
    /// Files walked but filtered out (size cap, exclude glob, etc.).
    pub skipped: u32,
}

/// Walk `root` honouring `.gitignore` + `cc-config` scope rules.
///
/// # Errors
///
/// Returns [`KernelError::GlobCompile`] when an ignore-glob in
/// [`cc_config::Config::ignore`] fails to compile, and
/// [`KernelError::Io`] when the walker cannot stat the root.
pub fn walk_repo(root: &Utf8Path, config: &Config) -> KernelResult<WalkOutcome> {
    let exclude = compile_excludes(config)?;
    let mut outcome = WalkOutcome::default();

    let mut builder = WalkBuilder::new(root.as_std_path());
    builder
        .standard_filters(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .require_git(false)
        .hidden(true)
        .parents(true);
    // Surface a top-level `.gitignore` even when the tree is not a git
    // repo. `require_git(false)` widens this further but doesn't always
    // pick the file up on Windows; explicit registration is belt-and-braces.
    let gitignore = root.join(".gitignore");
    if gitignore.as_std_path().is_file() {
        builder.add_ignore(gitignore.as_std_path());
    }
    let walker = builder.build();

    for entry in walker {
        match entry {
            Ok(dirent) => process_entry(root, &dirent, &exclude, &mut outcome),
            Err(err) => {
                tracing::warn!(
                    target: "cc_kernel::walker",
                    error_kind = %err,
                    "walker entry failed; skipping"
                );
                outcome.skipped = outcome.skipped.saturating_add(1);
            }
        }
    }

    Ok(outcome)
}

/// Compile the global ignore globs into a single `GlobSet`.
fn compile_excludes(config: &Config) -> KernelResult<GlobSet> {
    let mut patterns = config.ignore.paths.clone();
    if config.ignore.vendored {
        patterns.extend(default_vendored_patterns().iter().map(ToString::to_string));
    }
    if config.ignore.generated {
        patterns.extend(default_generated_patterns().iter().map(ToString::to_string));
    }
    for ext in &config.ignore.extensions {
        patterns.push(format!("**/*.{ext}"));
    }
    build_globset(&patterns, "ignore.paths").map_err(|source| KernelError::GlobCompile {
        field: "ignore.paths".to_owned(),
        source,
    })
}

const fn default_vendored_patterns() -> &'static [&'static str] {
    &[
        "vendor/**",
        "node_modules/**",
        ".venv/**",
        "venv/**",
        "target/**",
        ".git/**",
    ]
}

const fn default_generated_patterns() -> &'static [&'static str] {
    &[
        "**/*.pb.go",
        "**/*_pb2.py",
        "**/*_pb2.pyi",
        "**/*.gen.ts",
        "**/*.gen.go",
        "**/*.gen.rs",
    ]
}

/// Inspect a single walker entry; on the happy path the relative path
/// joins `outcome.included`, otherwise `outcome.skipped` is bumped.
fn process_entry(
    root: &Utf8Path,
    dirent: &ignore::DirEntry,
    exclude: &GlobSet,
    outcome: &mut WalkOutcome,
) {
    if !dirent.file_type().is_some_and(|ft| ft.is_file()) {
        return;
    }
    let Ok(absolute) = Utf8PathBuf::from_path_buf(dirent.path().to_path_buf()) else {
        outcome.skipped = outcome.skipped.saturating_add(1);
        return;
    };
    let relative = match absolute.strip_prefix(root) {
        Ok(rel) if !rel.as_str().is_empty() => rel.to_path_buf(),
        Ok(_) => return,
        Err(_) => absolute.clone(),
    };
    if exclude.is_match(relative.as_std_path()) {
        outcome.skipped = outcome.skipped.saturating_add(1);
        return;
    }
    if oversize(&absolute) {
        tracing::warn!(
            target: "cc_kernel::walker",
            path = %relative,
            "file exceeds size cap; skipping"
        );
        outcome.skipped = outcome.skipped.saturating_add(1);
        return;
    }
    outcome.included.push(relative);
}

/// True when the file at `absolute` is larger than [`DEFAULT_MAX_FILE_BYTES`].
fn oversize(absolute: &Utf8Path) -> bool {
    std::fs::metadata(absolute.as_std_path())
        .map(|m| m.len() > DEFAULT_MAX_FILE_BYTES)
        .unwrap_or(false)
}
