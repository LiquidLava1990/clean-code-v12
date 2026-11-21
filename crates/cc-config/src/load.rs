//! Filesystem I/O, defaults, merging, and pretty-print diffing.

use camino::Utf8Path;
use std::collections::BTreeMap;
use std::fs;

use crate::error::{ConfigError, Result};
use crate::model::{Config, ProjectConfig};
use crate::validate::validate;

const EXAMPLE_TEMPLATE: &str = include_str!("../examples/example.cc.toml");

impl Config {
    /// Read + parse + validate the config at `path`.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::Io`] — file unreadable.
    /// - [`ConfigError::Parse`] — TOML invalid.
    /// - validation errors (see [`crate::ConfigError`] variants).
    pub fn load(path: &Utf8Path) -> Result<Self> {
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let cfg: Self = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
        validate(&cfg)?;
        Ok(cfg)
    }

    /// Sensible defaults keyed off the repo root path.
    ///
    /// Project name comes from the final path component when present,
    /// otherwise `"unnamed"`. Validation always passes for the result.
    #[must_use]
    pub fn default_for_repo(root: &Utf8Path) -> Self {
        let name = root
            .file_name()
            .map_or_else(|| "unnamed".to_owned(), str::to_owned);
        Self {
            project: ProjectConfig {
                name,
                languages: Vec::new(),
                marker: Some(".cc/config.toml".into()),
            },
            ..Self::default()
        }
    }

    /// Three-way merge: `self` is the lower-priority layer, `other`
    /// wins on conflict. Used to layer global -> user -> repo config.
    ///
    /// Merge semantics:
    /// - scalars / `Option`s: `other` wins if `Some`/non-default.
    /// - `BTreeMap<rule_id, RuleConfig>`: per-key override (replace).
    /// - `Vec<String>` (ignore.paths, extensions, languages): concatenated, dedup preserved order.
    #[must_use]
    pub fn merge(mut self, other: Self) -> Self {
        merge_project(&mut self.project, other.project);
        merge_rules(&mut self.rules, other.rules);
        merge_ignore(&mut self.ignore, other.ignore);
        // baseline / runtime / fingerprint: `other` wins wholesale.
        self.baseline = other.baseline;
        self.runtime = other.runtime;
        self.fingerprint = other.fingerprint;
        self
    }

    /// Render a human-readable diff between two configs.
    ///
    /// Used by `ccv12 check --explain-config`. Format is intentionally
    /// loose — TOML round-trip with a `< / >` prefix per differing
    /// line. A pretty unified-diff is a P2 enhancement.
    #[must_use]
    pub fn display_diff(&self, other: &Self) -> String {
        let lhs = toml::to_string_pretty(self).unwrap_or_default();
        let rhs = toml::to_string_pretty(other).unwrap_or_default();
        diff_lines(&lhs, &rhs)
    }
}

fn merge_project(into: &mut ProjectConfig, from: ProjectConfig) {
    if !from.name.is_empty() {
        into.name = from.name;
    }
    if !from.languages.is_empty() {
        into.languages = from.languages;
    }
    if from.marker.is_some() {
        into.marker = from.marker;
    }
}

fn merge_rules(
    into: &mut BTreeMap<String, crate::model::RuleConfig>,
    from: BTreeMap<String, crate::model::RuleConfig>,
) {
    for (k, v) in from {
        into.insert(k, v);
    }
}

fn merge_ignore(into: &mut crate::model::IgnoreConfig, from: crate::model::IgnoreConfig) {
    extend_dedup(&mut into.paths, from.paths);
    extend_dedup(&mut into.extensions, from.extensions);
    into.generated = from.generated;
    into.vendored = from.vendored;
}

fn extend_dedup(target: &mut Vec<String>, additions: Vec<String>) {
    for item in additions {
        if !target.iter().any(|existing| existing == &item) {
            target.push(item);
        }
    }
}

/// Naive line-by-line diff sufficient for `display_diff`.
fn diff_lines(lhs: &str, rhs: &str) -> String {
    let l: Vec<&str> = lhs.lines().collect();
    let r: Vec<&str> = rhs.lines().collect();
    let mut out = String::new();
    let max = l.len().max(r.len());
    for i in 0..max {
        let lline = l.get(i).copied().unwrap_or("");
        let rline = r.get(i).copied().unwrap_or("");
        if lline != rline {
            if !lline.is_empty() {
                out.push_str("< ");
                out.push_str(lline);
                out.push('\n');
            }
            if !rline.is_empty() {
                out.push_str("> ");
                out.push_str(rline);
                out.push('\n');
            }
        }
    }
    out
}

/// Drop a fully-commented default config at `path`.
///
/// Used by `ccv12 init`.
///
/// # Errors
///
/// Returns [`ConfigError::WriteIo`] if the parent directory cannot
/// be created or the file cannot be written.
pub fn write_default(path: &Utf8Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| ConfigError::WriteIo {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    fs::write(path, EXAMPLE_TEMPLATE).map_err(|source| ConfigError::WriteIo {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Config, IgnoreConfig, RuleConfig};
    use crate::severity::Severity;
    use camino::Utf8PathBuf;

    fn tmp_path(name: &str) -> Utf8PathBuf {
        let dir = std::env::temp_dir().join(format!("cc-config-test-{}", uniq_id()));
        std::fs::create_dir_all(&dir).unwrap();
        Utf8PathBuf::from_path_buf(dir.join(name)).unwrap()
    }

    fn uniq_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        format!(
            "{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        )
    }

    #[test]
    fn default_config_validates() {
        let cfg = Config::default_for_repo(Utf8Path::new("/tmp/myrepo"));
        assert_eq!(cfg.project.name, "myrepo");
        validate(&cfg).expect("default config must validate");
    }

    #[test]
    fn write_default_emits_parseable_file() {
        let path = tmp_path("config.toml");
        write_default(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        // example.cc.toml must be valid + must validate
        validate(&loaded).expect("example must validate");
    }

    #[test]
    fn roundtrip_preserves_structure() {
        let mut cfg = Config::default_for_repo(Utf8Path::new("/tmp/repo"));
        cfg.rules.insert(
            "cc.shape.fn_length".into(),
            RuleConfig {
                severity_override: Some(Severity::Required),
                ..RuleConfig::default()
            },
        );
        let serialized = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(cfg, parsed);
    }

    #[test]
    fn merge_layered_repo_wins() {
        let mut global = Config::default_for_repo(Utf8Path::new("/repo"));
        global.ignore.paths.push("global/**".into());
        let mut user = Config::default();
        user.ignore.paths.push("user/**".into());
        let mut repo = Config::default();
        repo.ignore.paths.push("repo/**".into());
        repo.project.name = "winner".into();

        let merged = global.merge(user).merge(repo);
        assert_eq!(merged.project.name, "winner");
        assert!(merged.ignore.paths.iter().any(|p| p == "global/**"));
        assert!(merged.ignore.paths.iter().any(|p| p == "user/**"));
        assert!(merged.ignore.paths.iter().any(|p| p == "repo/**"));
    }

    #[test]
    fn ignore_defaults_keep_vendored_and_generated_on() {
        let cfg = IgnoreConfig::default();
        assert!(cfg.generated);
        assert!(cfg.vendored);
    }

    #[test]
    fn display_diff_shows_changed_lines() {
        let a = Config::default_for_repo(Utf8Path::new("/repo-a"));
        let b = Config::default_for_repo(Utf8Path::new("/repo-b"));
        let diff = a.display_diff(&b);
        assert!(diff.contains("repo-a") || diff.contains("repo-b"), "{diff}");
    }
}
