//! Glob-based path scoping helpers.
//!
//! Used by both [`crate::IgnoreConfig`] (repo-wide skip list) and
//! [`PathScope`] (per-rule include/exclude). Compilation is fallible
//! and produces an actionable [`crate::ConfigError::BadGlob`] on
//! malformed patterns.

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, Result};

/// Per-rule include/exclude scoping.
///
/// Empty `include` means *all paths*. Empty `exclude` means *no
/// paths excluded*. `exclude` wins over `include` on overlap.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PathScope {
    /// Glob patterns the rule applies to (empty = all).
    pub include: Vec<String>,
    /// Glob patterns the rule does NOT apply to.
    pub exclude: Vec<String>,
}

impl PathScope {
    /// Build the matchers; returns `(include, exclude)` globsets.
    ///
    /// Both fields are reported under `field_prefix` so the user
    /// can locate the bad pattern in their config.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BadGlob`] if any pattern fails to
    /// compile under `globset` syntax.
    pub fn compile(&self, field_prefix: &str) -> Result<(GlobSet, GlobSet)> {
        let inc = build_globset(&self.include, &format!("{field_prefix}.include"))?;
        let exc = build_globset(&self.exclude, &format!("{field_prefix}.exclude"))?;
        Ok((inc, exc))
    }
}

/// Compile a list of glob patterns into a `GlobSet`, attaching the
/// declared `field` to any error for actionable reporting.
///
/// # Errors
///
/// Returns [`ConfigError::BadGlob`] if a pattern fails to compile
/// or the final set fails to build.
pub fn build_globset(patterns: &[String], field: &str) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        let glob = Glob::new(pat).map_err(|source| ConfigError::BadGlob {
            pattern: pat.clone(),
            field: field.to_owned(),
            source: Box::new(source),
        })?;
        builder.add(glob);
    }
    builder.build().map_err(|source| ConfigError::BadGlob {
        pattern: patterns.join(", "),
        field: field.to_owned(),
        source: Box::new(source),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn glob_matching_vendor_pattern() {
        let gs = build_globset(&["vendor/**/*.go".into()], "test").unwrap();
        assert!(gs.is_match(Path::new("vendor/foo/bar.go")));
        assert!(gs.is_match(Path::new("vendor/deep/nested/x.go")));
        assert!(!gs.is_match(Path::new("src/foo.go")));
        assert!(!gs.is_match(Path::new("vendor/foo/bar.py")));
    }

    #[test]
    fn empty_globset_matches_nothing() {
        let gs = build_globset(&[], "test").unwrap();
        assert!(!gs.is_match(Path::new("anything")));
    }

    #[test]
    fn bad_glob_surfaces_field_name() {
        let err = build_globset(&["[unclosed".into()], "rules.foo.include").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("rules.foo.include"), "msg = {msg}");
        assert!(msg.contains("[unclosed"), "msg = {msg}");
    }
}
