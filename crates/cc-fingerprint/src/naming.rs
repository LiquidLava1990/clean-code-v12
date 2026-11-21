//! Naming-style classification + per-`NodeKind` distribution.
//!
//! A repo's *naming distribution* — the relative frequency of snake / camel /
//! pascal / screaming / kebab / mixed identifiers per node kind — is the
//! statistical baseline against which downstream rules flag drift outliers.

use std::collections::BTreeMap;

use cc_cpg::NodeKind;
use serde::{Deserialize, Serialize};

/// Minimum samples for a kind before [`NamingDistribution::dominant`] returns
/// anything. Smaller cohorts produce too-noisy dominants.
const MIN_SAMPLES_FOR_DOMINANCE: u64 = 10;

/// Minimum share of the dominant style required to call it "dominant" for
/// outlier-flagging purposes. ≥80% is the agreed Clean Code V12 threshold.
const DOMINANCE_THRESHOLD: f64 = 0.80;

/// One of the canonical naming conventions found in source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NamingStyle {
    /// `snake_case`.
    SnakeCase,
    /// `camelCase`.
    CamelCase,
    /// `PascalCase`.
    PascalCase,
    /// `SCREAMING_SNAKE_CASE`.
    ScreamingSnake,
    /// `kebab-case`.
    KebabCase,
    /// Mixed / unclassifiable (e.g. `iOS`, `httpServer_v2`).
    Mixed,
}

impl NamingStyle {
    /// All six variants in canonical order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::SnakeCase,
            Self::CamelCase,
            Self::PascalCase,
            Self::ScreamingSnake,
            Self::KebabCase,
            Self::Mixed,
        ]
    }
}

/// Skip identifiers that are too short or are dunder methods — they pollute
/// the distribution without carrying style signal.
#[must_use]
pub fn should_skip_for_classification(name: &str) -> bool {
    if name.len() < 2 {
        return true;
    }
    if name.starts_with("__") && name.ends_with("__") {
        return true;
    }
    false
}

/// Compact summary of the character classes present in an identifier —
/// the single source of truth for [`classify_name`] decisions.
#[derive(Debug, Clone, Copy)]
struct CharClasses {
    has_underscore: bool,
    has_upper: bool,
    has_lower: bool,
    first_upper: bool,
}

impl CharClasses {
    fn of(trimmed: &str) -> Self {
        Self {
            has_underscore: trimmed.contains('_'),
            has_upper: trimmed.chars().any(|c| c.is_ascii_uppercase()),
            has_lower: trimmed.chars().any(|c| c.is_ascii_lowercase()),
            first_upper: trimmed
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase()),
        }
    }
}

/// Classify an identifier into a [`NamingStyle`].
///
/// Strips a single leading underscore (private marker) and a trailing
/// underscore before classifying. See module docs for edge cases.
#[must_use]
pub fn classify_name(raw: &str) -> NamingStyle {
    let trimmed = strip_privacy_markers(raw);
    if trimmed.is_empty() {
        return NamingStyle::Mixed;
    }
    if trimmed.contains('-') {
        return NamingStyle::KebabCase;
    }
    let classes = CharClasses::of(trimmed);
    if let Some(style) = classify_by_underscore(classes) {
        return style;
    }
    classify_by_case(trimmed, classes)
}

/// Resolve the style for identifiers containing an underscore. Returns
/// `None` when no underscore is present so the caller can fall through
/// to case-based classification.
fn classify_by_underscore(c: CharClasses) -> Option<NamingStyle> {
    if !c.has_underscore {
        return None;
    }
    if !c.has_lower && c.has_upper {
        return Some(NamingStyle::ScreamingSnake);
    }
    if c.has_lower && !c.has_upper {
        return Some(NamingStyle::SnakeCase);
    }
    Some(NamingStyle::Mixed)
}

/// Resolve the style for identifiers without underscores using only the
/// case profile. Caller has already excluded empty / kebab / underscore
/// shapes.
fn classify_by_case(trimmed: &str, c: CharClasses) -> NamingStyle {
    // All-uppercase (no lowercase anywhere) is ScreamingSnake — handle
    // before the consecutive-upper check so canonical screaming names
    // don't fall through to Mixed.
    if c.has_upper && !c.has_lower {
        return NamingStyle::ScreamingSnake;
    }
    if !c.has_upper && !c.has_lower {
        return NamingStyle::SnakeCase;
    }
    // Consecutive uppercase letters with no following lowercase are not
    // canonical camel/Pascal — they are the `iOS` / `XMLParser` mixed
    // territory.
    if has_consecutive_uppercase_run(trimmed) {
        return NamingStyle::Mixed;
    }
    if c.first_upper && c.has_lower {
        return NamingStyle::PascalCase;
    }
    if !c.first_upper && c.has_upper {
        return NamingStyle::CamelCase;
    }
    if !c.first_upper && !c.has_upper {
        return NamingStyle::SnakeCase;
    }
    NamingStyle::Mixed
}

/// Returns true if `s` has two or more uppercase letters in a row that are
/// not followed by a lowercase letter — the `iOS` / `OSx` pattern.
const fn has_consecutive_uppercase_run(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_uppercase() && i + 1 < bytes.len() && bytes[i + 1].is_ascii_uppercase()
        {
            // Found two upper in a row. If the run ends at end-of-string or
            // is followed by a non-lowercase, it's a mixed run.
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_uppercase() {
                j += 1;
            }
            if j == bytes.len() || !bytes[j].is_ascii_lowercase() {
                return true;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

fn strip_privacy_markers(raw: &str) -> &str {
    let s = raw.strip_prefix('_').unwrap_or(raw);
    s.strip_suffix('_').unwrap_or(s)
}

/// Per-style counts for a single [`NodeKind`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StyleCounts {
    /// `snake_case` count.
    pub snake: u64,
    /// `camelCase` count.
    pub camel: u64,
    /// `PascalCase` count.
    pub pascal: u64,
    /// `SCREAMING_SNAKE` count.
    pub screaming: u64,
    /// `kebab-case` count.
    pub kebab: u64,
    /// Mixed / unclassifiable count.
    pub mixed: u64,
}

impl StyleCounts {
    /// Increment the bucket for `style`.
    pub fn record(&mut self, style: NamingStyle) {
        match style {
            NamingStyle::SnakeCase => self.snake += 1,
            NamingStyle::CamelCase => self.camel += 1,
            NamingStyle::PascalCase => self.pascal += 1,
            NamingStyle::ScreamingSnake => self.screaming += 1,
            NamingStyle::KebabCase => self.kebab += 1,
            NamingStyle::Mixed => self.mixed += 1,
        }
    }

    /// Total samples across all styles.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.snake + self.camel + self.pascal + self.screaming + self.kebab + self.mixed
    }

    /// Count for a specific style.
    #[must_use]
    pub const fn count_for(&self, style: NamingStyle) -> u64 {
        match style {
            NamingStyle::SnakeCase => self.snake,
            NamingStyle::CamelCase => self.camel,
            NamingStyle::PascalCase => self.pascal,
            NamingStyle::ScreamingSnake => self.screaming,
            NamingStyle::KebabCase => self.kebab,
            NamingStyle::Mixed => self.mixed,
        }
    }

    /// Dominant style if any single bucket holds at least
    /// `DOMINANCE_THRESHOLD` of the total and the total is at least
    /// `MIN_SAMPLES_FOR_DOMINANCE`.
    #[must_use]
    pub fn dominant(&self) -> Option<NamingStyle> {
        let total = self.total();
        if total < MIN_SAMPLES_FOR_DOMINANCE {
            return None;
        }
        let mut best: Option<(NamingStyle, u64)> = None;
        for style in NamingStyle::all() {
            let count = self.count_for(*style);
            match best {
                None => best = Some((*style, count)),
                Some((_, prev)) if count > prev => best = Some((*style, count)),
                _ => {}
            }
        }
        let (style, count) = best?;
        #[allow(clippy::cast_precision_loss)] // share is a heuristic; counts << 2^52
        let share = count as f64 / total as f64;
        if share >= DOMINANCE_THRESHOLD {
            Some(style)
        } else {
            None
        }
    }
}

/// Per-`NodeKind` naming distribution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamingDistribution {
    per_kind: BTreeMap<NodeKind, StyleCounts>,
}

impl NamingDistribution {
    /// Empty distribution.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a single name observation under `kind`.
    pub fn record(&mut self, kind: NodeKind, name: &str) {
        if should_skip_for_classification(name) {
            return;
        }
        let style = classify_name(name);
        self.per_kind.entry(kind).or_default().record(style);
    }

    /// Borrow the count bucket for `kind` if any samples have been recorded.
    #[must_use]
    pub fn counts(&self, kind: NodeKind) -> Option<&StyleCounts> {
        self.per_kind.get(&kind)
    }

    /// Dominant style for `kind`, if a clear ≥80% winner exists across ≥10
    /// samples.
    #[must_use]
    pub fn dominant(&self, kind: NodeKind) -> Option<NamingStyle> {
        self.counts(kind).and_then(StyleCounts::dominant)
    }

    /// Return true iff `name` is an outlier under `kind` — a clear dominant
    /// style exists and `name` does not match it.
    #[must_use]
    pub fn is_outlier(&self, kind: NodeKind, name: &str) -> bool {
        if should_skip_for_classification(name) {
            return false;
        }
        let Some(dominant) = self.dominant(kind) else {
            return false;
        };
        classify_name(name) != dominant
    }

    /// Total identifiers seen across all kinds.
    #[must_use]
    pub fn sample_count(&self) -> u64 {
        self.per_kind.values().map(StyleCounts::total).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_snake() {
        assert_eq!(classify_name("my_function"), NamingStyle::SnakeCase);
        assert_eq!(classify_name("simple"), NamingStyle::SnakeCase);
    }

    #[test]
    fn classify_camel() {
        assert_eq!(classify_name("myFunction"), NamingStyle::CamelCase);
        assert_eq!(classify_name("doStuffNow"), NamingStyle::CamelCase);
    }

    #[test]
    fn classify_pascal() {
        assert_eq!(classify_name("MyClass"), NamingStyle::PascalCase);
        assert_eq!(classify_name("ProjectFingerprint"), NamingStyle::PascalCase);
    }

    #[test]
    fn classify_screaming() {
        assert_eq!(classify_name("HTTP_PROXY"), NamingStyle::ScreamingSnake);
        assert_eq!(classify_name("MAX"), NamingStyle::ScreamingSnake);
    }

    #[test]
    fn classify_kebab() {
        assert_eq!(classify_name("my-package"), NamingStyle::KebabCase);
    }

    #[test]
    fn classify_mixed() {
        assert_eq!(classify_name("iOS"), NamingStyle::Mixed);
    }

    #[test]
    fn skip_dunder_and_short() {
        assert!(should_skip_for_classification("__init__"));
        assert!(should_skip_for_classification("i"));
        assert!(should_skip_for_classification("_"));
        assert!(!should_skip_for_classification("foo"));
    }

    #[test]
    fn strip_underscore_marker() {
        assert_eq!(classify_name("_private_helper"), NamingStyle::SnakeCase);
        assert_eq!(classify_name("trailing_"), NamingStyle::SnakeCase);
    }

    #[test]
    fn dominant_requires_threshold_and_samples() {
        let mut counts = StyleCounts::default();
        for _ in 0..9 {
            counts.record(NamingStyle::SnakeCase);
        }
        assert_eq!(counts.dominant(), None, "below sample floor");

        counts.record(NamingStyle::SnakeCase);
        assert_eq!(counts.dominant(), Some(NamingStyle::SnakeCase));

        for _ in 0..3 {
            counts.record(NamingStyle::CamelCase);
        }
        assert_eq!(counts.dominant(), None, "share below 80%");
    }

    #[test]
    fn distribution_outlier_check() {
        let mut dist = NamingDistribution::new();
        for _ in 0..9 {
            dist.record(NodeKind::Function, "snake_thing");
        }
        dist.record(NodeKind::Function, "camelThing");
        assert_eq!(
            dist.dominant(NodeKind::Function),
            Some(NamingStyle::SnakeCase)
        );
        assert!(dist.is_outlier(NodeKind::Function, "myFn"));
        assert!(!dist.is_outlier(NodeKind::Function, "my_fn"));
    }

    #[test]
    fn distribution_no_dominant_no_outlier() {
        let mut dist = NamingDistribution::new();
        for _ in 0..5 {
            dist.record(NodeKind::Function, "snake_one");
            dist.record(NodeKind::Function, "camelOne");
        }
        assert_eq!(dist.dominant(NodeKind::Function), None);
        assert!(!dist.is_outlier(NodeKind::Function, "myFn"));
        assert!(!dist.is_outlier(NodeKind::Function, "my_fn"));
    }
}
