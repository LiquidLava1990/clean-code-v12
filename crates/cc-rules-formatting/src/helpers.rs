//! Internal helpers shared across Family-26 formatting probes.
//!
//! The pack works at file-bytes granularity rather than over the CPG
//! AST: formatting drift is intrinsically a textual property and the
//! lifted IR has already discarded the whitespace we care about. The
//! helpers therefore centralise (a) iterating every `NodeKind::File`
//! batch, (b) reading the corresponding source bytes, (c) skipping
//! test fixtures, and (d) building findings.

use camino::Utf8PathBuf;
use cc_cpg::NodeKind;
use cc_finding::{
    ActionableMessage, Category, Confidence, CostClaim, Evidence, Finding, FindingBuilder,
    Location, Position, ProbeVersion, Remediation, Severity,
};
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::RuleContext;

use crate::pack::BuiltinFormattingPack;

/// Probe-pack identity stamped on every Family-26 finding.
#[must_use]
pub(crate) fn probe_version() -> ProbeVersion {
    ProbeVersion::new(
        BuiltinFormattingPack::PACK_ID,
        BuiltinFormattingPack::PACK_SEMVER,
        cc_rules::KERNEL_API_VERSION,
        None,
    )
}

/// Build a [`Location`] anchored at `(line, 1)` of `file` — formatting
/// findings are always file-or-line-scoped, never node-scoped.
#[must_use]
pub(crate) fn location_for_file(file: Utf8PathBuf, line: u32) -> Location {
    let pos = Position::new(line.max(1), 1, 0);
    Location {
        file,
        start: pos,
        end: pos,
        node_id: None,
        function_qualified_name: None,
    }
}

/// True iff `path` looks like a test file across the four supported
/// languages. Re-implemented from the Tier-0 helper so the pack stays
/// independent of `cc-rules-tier0`.
#[must_use]
pub(crate) fn is_test_file_path(path: &Utf8PathBuf) -> bool {
    let s = path.as_str().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
    if has_test_segment(&lower) {
        return true;
    }
    match path.file_stem() {
        Some(stem) => is_test_stem(&stem.to_ascii_lowercase()),
        None => false,
    }
}

fn has_test_segment(lower: &str) -> bool {
    lower.contains("/tests/")
        || lower.contains("/test/")
        || lower.contains("/__tests__/")
        || lower.contains("/fixtures/")
        || lower.contains("/testdata/")
        || lower.starts_with("tests/")
        || lower.starts_with("test/")
}

fn is_test_stem(stem_lower: &str) -> bool {
    stem_lower == "tests"
        || stem_lower == "test"
        || stem_lower.starts_with("test_")
        || stem_lower.ends_with("_test")
        || stem_lower.ends_with(".test")
        || stem_lower.ends_with(".spec")
}

/// Iterate every `(path, bytes)` pair in the current rule context whose
/// enclosing file is not a test fixture. Probes that need to skip
/// non-source files filter the path further on top of this.
pub(crate) fn each_source_file<'a>(
    ctx: &'a RuleContext<'a>,
) -> impl Iterator<Item = (Utf8PathBuf, &'a [u8])> + 'a {
    nodes_of_kind(ctx.batch, NodeKind::File).filter_map(|node| {
        let raw = string_prop(ctx.batch, node.id, "path")?;
        let path = Utf8PathBuf::from(raw);
        if is_test_file_path(&path) {
            return None;
        }
        let bytes = ctx.source.get(path.as_path());
        Some((path, bytes))
    })
}

/// True iff `line` looks like it embeds a URL, file URI, or other
/// long token a human cannot reasonably wrap. Heuristic — kept loose;
/// the [`Severity::Nit`] severity means false negatives are cheap.
#[must_use]
pub(crate) fn looks_like_url(line: &str) -> bool {
    line.contains("http://")
        || line.contains("https://")
        || line.contains("file://")
        || line.contains("file:")
        || line.contains("data:")
        || line.contains("git+")
}

/// Inputs every Family-26 probe supplies when emitting a [`Finding`].
#[derive(Debug)]
pub(crate) struct FormattingFindingBlueprint {
    /// Stable rule identifier, e.g. `"cc.fmt.long_line"`.
    pub rule_id: &'static str,
    /// Severity to stamp on the finding (default Nit for this pack).
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
    /// Blocking-debt weight for score impact (typically 0 for Nits).
    pub weight: u32,
}

/// Build a complete [`Finding`] from a [`FormattingFindingBlueprint`].
pub(crate) fn build_finding(blueprint: FormattingFindingBlueprint) -> Finding {
    let FormattingFindingBlueprint {
        rule_id,
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
        .category(Category::Shape)
        .location(location)
        .message(message)
        .evidence(evidence)
        .severity(severity)
        .confidence(confidence.get())
        .cost(CostClaim::BlockingDebt { weight })
        .probe_version(probe_version())
        .build()
        .expect("Family-26 finding builder receives all required fields")
}

/// True iff `path`'s extension matches one of the source-language
/// extensions this pack recognises (Python / Rust / Go / TS / JS).
/// Used by probes that should skip non-source files like markdown,
/// JSON, YAML.
#[must_use]
pub(crate) fn has_source_extension(path: &Utf8PathBuf) -> bool {
    matches!(
        path.extension(),
        Some("py" | "rs" | "go" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs")
    )
}
