//! Hardcoded rule-id registry for Phase 1.
//!
//! Future PR: replace with a dynamic registry sourced from `cc-rules`
//! at link time so probe packs can register new ids without touching
//! `cc-config`. Until then, this is the single source of truth.

use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};

use crate::severity::Severity;

/// The 16 Tier-0 (Family 0) forever-rule ids.
///
/// Source: the Tier-0 forever-rules table in `README.md`. These rules cannot be
/// disabled per repo (validated at config load time).
pub const TIER_0_RULE_IDS: &[&str] = &[
    "cc.shape.fn_length",
    "cc.shape.file_length",
    "cc.shape.nesting_depth",
    "cc.shape.param_count",
    "cc.shape.cyclomatic",
    "cc.shape.cognitive",
    "cc.shape.duplication",
    "cc.shape.dead_code",
    "cc.shape.type_coverage",
    "cc.shape.naming",
    "cc.shape.early_return",
    "cc.shape.inheritance_depth",
    "cc.bug.bare_catch",
    "cc.bug.error_message_quality",
    "cc.meta.touch_ratchet",
    "cc.meta.new_file_gate",
];

/// Set of all known rule ids.
///
/// Phase 1: identical to `TIER_0_RULE_IDS`. Phase 2+ will include
/// non-Tier-0 rule packs and grow this set.
pub static RULE_REGISTRY: Lazy<HashSet<&'static str>> =
    Lazy::new(|| TIER_0_RULE_IDS.iter().copied().collect());

/// Set of Tier-0 (Family 0) rule ids — fast-path lookup.
pub static TIER_0_RULES: Lazy<HashSet<&'static str>> =
    Lazy::new(|| TIER_0_RULE_IDS.iter().copied().collect());

/// Intrinsic severity per rule.
///
/// Validation uses this to decide whether a `severity_override` is
/// a downgrade (allowed for non-Family-0) or an upgrade (rejected).
/// Sourced from `docs/design/TIER_0_ALGORITHMS.md`.
pub static INTRINSIC_SEVERITY: Lazy<HashMap<&'static str, Severity>> = Lazy::new(|| {
    let mut m = HashMap::new();
    // Tier-0 rules are all Blocker by default.
    for id in TIER_0_RULE_IDS {
        m.insert(*id, Severity::Blocker);
    }
    m
});

/// Look up the intrinsic severity for a rule id, or `Required` as a
/// safe default for unknown-but-registered rules (defensive — should
/// never happen because validation rejects unknown ids first).
#[must_use]
pub fn intrinsic_severity_for(id: &str) -> Severity {
    INTRINSIC_SEVERITY
        .get(id)
        .copied()
        .unwrap_or(Severity::Required)
}

/// Check whether `id` is a Tier-0 rule.
#[must_use]
pub fn is_tier0(id: &str) -> bool {
    TIER_0_RULES.contains(id)
}

/// Check whether `id` is registered (any tier).
#[must_use]
pub fn is_registered(id: &str) -> bool {
    RULE_REGISTRY.contains(id)
}

/// Suggest close matches for a typo'd rule id.
///
/// Uses Damerau-Levenshtein-ish edit distance ≤ 2 against the full
/// registry. Returns up to 3 suggestions, sorted by distance.
#[must_use]
pub fn suggest_rules(id: &str) -> Vec<&'static str> {
    let mut scored: Vec<(usize, &'static str)> = RULE_REGISTRY
        .iter()
        .map(|known| (edit_distance(id, known), *known))
        .filter(|(d, _)| *d <= 3)
        .collect();
    scored.sort_by_key(|(d, name)| (*d, *name));
    scored.into_iter().take(3).map(|(_, name)| name).collect()
}

/// Simple Levenshtein distance (bounded — Phase 1 keeps it small).
///
/// Suffices for typo detection in 30-char rule ids; a smarter metric
/// (Damerau or Jaro-Winkler) is a P2 enhancement.
fn edit_distance(a: &str, b: &str) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let (m, n) = (a_bytes.len(), b_bytes.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = usize::from(a_bytes[i - 1] != b_bytes[j - 1]);
            curr[j] = (curr[j - 1] + 1).min(prev[j] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_16_tier0_rules() {
        assert_eq!(TIER_0_RULE_IDS.len(), 16);
        assert_eq!(RULE_REGISTRY.len(), 16);
    }

    #[test]
    fn is_tier0_recognises_canonical_ids() {
        assert!(is_tier0("cc.shape.fn_length"));
        assert!(!is_tier0("cc.unknown.rule"));
    }

    #[test]
    fn suggest_typo_returns_close_match() {
        let s = suggest_rules("cc.shape.fn_lenght");
        assert!(s.contains(&"cc.shape.fn_length"), "got {s:?}");
    }

    #[test]
    fn edit_distance_basic() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", "abc"), 0);
    }
}
