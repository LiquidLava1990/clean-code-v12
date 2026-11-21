//! Internal helpers shared across Family-15 (i18n + a11y) probes.
//!
//! Re-implements the small set of traversal primitives every Family-15
//! rule needs so the pack stays sibling-independent of the other Phase-5
//! packs.

use camino::Utf8PathBuf;
use cc_cpg::{CpgWriteBatch, NodeId, NodeKind};
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{ast_parent, node_kind, range_prop, string_prop};

use crate::pack::BuiltinI18nA11yPack;

/// Locale literals the [`crate::hardcoded_locale`] probe flags. Matched
/// as exact substrings of a [`NodeKind::Literal`] string value.
pub(crate) const LOCALE_PATTERN_TABLE: &[&str] = &[
    "en_US",
    "en-US",
    "fr_FR",
    "fr-FR",
    "de_DE",
    "de-DE",
    "ja_JP",
    "ja-JP",
    "zh_CN",
    "zh-CN",
    "pt_BR",
    "pt-BR",
    "Europe/Paris",
    "America/New_York",
];

/// Inline-style colour patterns the [`crate::color_only_signal`] probe
/// flags. Matched case-insensitively as substrings of source bytes.
pub(crate) const COLOR_PATTERNS: &[&str] = &[
    "color: red",
    "color:red",
    "color: #ff0000",
    "color:#ff0000",
    "color: #f00",
    "color:#f00",
    "style.color = \"red\"",
    "style.color='red'",
    "style.color = 'red'",
];

/// Iconography / aria hints the colour-only probe accepts as evidence
/// that the colour is paired with a non-visual signal. Matched
/// case-insensitively.
pub(crate) const ICON_HINT_KEYWORDS: &[&str] = &[
    "aria-label",
    "<svg",
    "icon",
    "iconerror",
    "iconwarn",
    "iconwarning",
    "iconinfo",
    "role=",
];

/// Probe-pack identity stamped on every Family-15 finding.
#[must_use]
pub(crate) const fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinI18nA11yPack::PACK_ID,
        BuiltinI18nA11yPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Walk the `AST_PARENT` chain to the enclosing [`NodeKind::File`] and
/// return its `path` string property. Bounded to 256 hops.
#[must_use]
pub(crate) fn enclosing_file_path(batch: &CpgWriteBatch, mut id: NodeId) -> Option<Utf8PathBuf> {
    for _ in 0..256_u16 {
        if node_kind(batch, id) == Some(NodeKind::File) {
            return string_prop(batch, id, "path").map(Utf8PathBuf::from);
        }
        id = ast_parent(batch, id)?;
    }
    None
}

/// Build a [`Location`] anchored at the node's `range` property, falling
/// back to the start of the file when the property is missing.
pub(crate) fn location_from_node(batch: &CpgWriteBatch, id: NodeId, file: Utf8PathBuf) -> Location {
    let (start, end) = range_prop(batch, id, "range").map_or_else(
        || {
            let zero = Position::new(1, 1, 0);
            (zero, zero)
        },
        |r| {
            (
                Position::new(r.start.line, r.start.column, r.start.offset),
                Position::new(r.end.line, r.end.column, r.end.offset),
            )
        },
    );
    Location {
        file,
        start,
        end,
        node_id: Some(cc_finding::NodeId::new(id.get().to_string())),
        function_qualified_name: string_prop(batch, id, "name").map(str::to_owned),
    }
}

/// Build a [`Location`] anchored at byte offset `offset` inside `file`.
/// Used by source-bytes scans (`<img>`, inline-style colour) where the
/// hit is not associated with a CPG node.
pub(crate) fn location_at_offset(
    file: Utf8PathBuf,
    bytes: &[u8],
    offset: usize,
    span: usize,
) -> Location {
    let start = position_for_offset(bytes, offset);
    let end_off = offset.saturating_add(span).min(bytes.len());
    let end = position_for_offset(bytes, end_off);
    Location {
        file,
        start,
        end,
        node_id: None,
        function_qualified_name: None,
    }
}

/// Convert a byte offset into a [`Position`] (1-indexed line, 1-indexed
/// column, raw byte offset). Counts `\n` only — `\r\n` collapses to one
/// new-line because the column reset is what matters for human reading.
fn position_for_offset(bytes: &[u8], offset: usize) -> Position {
    let cap = offset.min(bytes.len());
    let mut line: u32 = 1;
    let mut col: u32 = 1;
    for byte in &bytes[..cap] {
        if *byte == b'\n' {
            line = line.saturating_add(1);
            col = 1;
        } else {
            col = col.saturating_add(1);
        }
    }
    let off = u32::try_from(offset).unwrap_or(u32::MAX);
    Position::new(line, col, off)
}

/// True iff `path` looks like a test file across the four supported
/// languages.
#[must_use]
pub(crate) fn is_test_file_path(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
    if has_test_segment(&lower) {
        return true;
    }
    path.file_stem()
        .is_some_and(|stem| is_test_stem(&stem.to_ascii_lowercase()))
}

fn has_test_segment(lower: &str) -> bool {
    lower.contains("/tests/")
        || lower.contains("/test/")
        || lower.contains("/__tests__/")
        || lower.starts_with("tests/")
        || lower.starts_with("test/")
}

fn is_test_stem(stem_lower: &str) -> bool {
    matches!(stem_lower, "tests" | "test")
        || stem_lower.starts_with("test_")
        || stem_lower.ends_with("_test")
        || stem_lower.ends_with(".test")
        || stem_lower.ends_with(".spec")
}

/// True iff `path` is a source file inside a rule-pack crate
/// (`crates/cc-rules-*/src/...`). Probes that scan source text for their
/// own detector needles skip these to avoid rule-on-rule noise — the
/// `LOCALE_PATTERN_TABLE` and `COLOR_PATTERNS` constants in this crate
/// would otherwise self-flag.
#[must_use]
pub(crate) fn looks_like_rule_pack_source(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/").to_ascii_lowercase();
    s.contains("/cc-rules-") && s.contains("/src/")
}

/// True iff the [`NodeKind::File`] node carries a JSX-flavour language
/// tag (`tsx` / `jsx` / `javascript` / `typescript`). Rule-of-thumb
/// match: a11y probes target the React tree.
#[must_use]
pub(crate) fn is_jsx_like_language(batch: &CpgWriteBatch, file_id: NodeId) -> bool {
    let Some(lang) = string_prop(batch, file_id, "language") else {
        return false;
    };
    let lower = lang.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "tsx" | "jsx" | "javascript" | "typescript" | "javascriptreact" | "typescriptreact"
    )
}

/// Inputs every Family-15 rule supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct I18nA11yFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.i18n.hardcoded_locale"`.
    pub rule_id: &'static str,
    /// Top-level finding category — `I18n` or `A11y` per probe.
    pub category: Category,
    /// Severity to stamp on the finding.
    pub severity: Severity,
    /// Confidence (0..=1) the rule has in this finding.
    pub confidence: Confidence,
    /// Source location where the issue manifests.
    pub location: Location,
    /// One-line headline shown first in any sink.
    pub headline: String,
    /// Multi-line explanation covering what + why.
    pub explanation: String,
    /// Concrete remediation guidance the user can act on.
    pub remediation: Remediation,
    /// Source-code snippet anchoring the finding (may be empty).
    pub snippet: String,
    /// Blocking-debt weight for score impact.
    pub weight: u32,
}

/// Build a complete [`Finding`] from an [`I18nA11yFindingBlueprint`].
pub(crate) fn build_finding(blueprint: I18nA11yFindingBlueprint) -> Finding {
    let I18nA11yFindingBlueprint {
        rule_id,
        category,
        severity,
        confidence,
        location,
        headline,
        explanation,
        remediation,
        snippet,
        weight,
    } = blueprint;
    let evidence = Evidence::from_snippet(snippet);
    let message = ActionableMessage::new(headline, explanation, remediation);
    FindingBuilder::new()
        .rule_id(rule_id)
        .category(category)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-15 finding builder receives all required fields")
}
