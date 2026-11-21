//! SARIF 2.1.0 document model.
//!
//! These structs mirror the subset of the SARIF 2.1.0 schema that
//! cc-sarif produces. Optional fields use `#[serde(skip_serializing_if = "Option::is_none")]`
//! / empty-vec elision so the emitted JSON stays close to what GitHub
//! code-scanning + microsoft/sarif-tools `validate` accept.
//!
//! Schema reference: <https://json.schemastore.org/sarif-2.1.0.json>.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// SARIF schema URI emitted on every document.
pub const SARIF_SCHEMA_URI: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// SARIF spec version string.
pub const SARIF_VERSION: &str = "2.1.0";

/// Top-level SARIF document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SarifDocument {
    /// The `$schema` URI — pinned to SARIF 2.1.0.
    #[serde(rename = "$schema")]
    pub schema: String,
    /// Spec version. Always `"2.1.0"`.
    pub version: String,
    /// One run per analysis invocation. cc-sarif emits exactly one.
    pub runs: Vec<Run>,
}

/// A single SARIF run — one tool invocation against one set of artifacts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    /// Tool that produced this run.
    pub tool: Tool,
    /// Findings, mapped from `cc-finding::Finding`.
    pub results: Vec<SarifResult>,
    /// Optional invocation block (timing, command line, exit code).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<Invocation>>,
    /// Optional URI base map (relative paths use `%SRCROOT%`).
    #[serde(rename = "originalUriBaseIds", skip_serializing_if = "Option::is_none")]
    pub original_uri_base_ids: Option<BTreeMap<String, ArtifactLocation>>,
}

/// Tool descriptor — driver + (unused) extensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    /// Primary driver component (the cc kernel itself).
    pub driver: ToolComponent,
}

/// One tool component (driver or extension).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolComponent {
    /// Display name, e.g. `"clean-code-v12"`.
    pub name: String,
    /// Semver of the producer, e.g. `"0.1.0"`.
    pub version: String,
    /// Optional public docs URL.
    #[serde(rename = "informationUri", skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    /// Rule descriptors, deduped from emitted findings.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub rules: Vec<ReportingDescriptor>,
}

/// SARIF rule descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportingDescriptor {
    /// Stable rule slug, e.g. `"cc.shape.fn_length"`.
    pub id: String,
    /// Human-friendly name. cc-sarif sets this equal to `id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Short description shown in IDE rule pickers.
    #[serde(rename = "shortDescription", skip_serializing_if = "Option::is_none")]
    pub short_description: Option<MultiformatMessageString>,
    /// Long-form description.
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    pub full_description: Option<MultiformatMessageString>,
    /// Permalink to rule docs.
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    /// Default reporting configuration (severity, enablement).
    #[serde(
        rename = "defaultConfiguration",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_configuration: Option<ReportingConfiguration>,
}

/// Default reporting config — severity + enablement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportingConfiguration {
    /// Default level (`"error" | "warning" | "note" | "none"`).
    pub level: String,
    /// Whether the rule is enabled by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// SARIF message with both plain-text and markdown forms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiformatMessageString {
    /// Plain-text form (required by SARIF spec).
    pub text: String,
    /// Optional markdown form.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

/// Plain message (text + optional markdown). Used on results + locations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Plain-text message body.
    pub text: String,
    /// Optional markdown rendering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

/// One SARIF result (== one `cc-finding::Finding`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)] // contains serde_json::Value
pub struct SarifResult {
    /// Rule id this result violates.
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    /// Severity mapping (`"error" | "warning" | "note"`).
    pub level: String,
    /// Human-facing message.
    pub message: Message,
    /// Source locations (always at least one).
    pub locations: Vec<Location>,
    /// Secondary locations (dataflow, dup partners).
    #[serde(
        rename = "relatedLocations",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub related_locations: Vec<Location>,
    /// Stable hashes that survive re-formatting.
    #[serde(
        rename = "partialFingerprints",
        skip_serializing_if = "BTreeMap::is_empty",
        default
    )]
    pub partial_fingerprints: BTreeMap<String, String>,
    /// Strict equality fingerprints (unused for now).
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub fingerprints: BTreeMap<String, String>,
    /// Auto-applicable repairs.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub fixes: Vec<Fix>,
    /// Cross-cutting metadata (cost, confidence, suggested rewrites).
    #[serde(skip_serializing_if = "serde_json::Value::is_null", default)]
    pub properties: serde_json::Value,
}

/// One physical (file/range) plus optional message annotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// File + region.
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
    /// Optional annotation explaining this location's role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
}

/// File reference + source-range pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalLocation {
    /// Artifact (file) being referenced.
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    /// Source range inside the artifact.
    pub region: Region,
}

/// Reference to an artifact (file) — URI relative to a base id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactLocation {
    /// Project-relative URI string (forward slashes).
    pub uri: String,
    /// Optional base-id key (e.g. `"%SRCROOT%"`).
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

/// Source-text region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    /// 1-indexed start line.
    #[serde(rename = "startLine")]
    pub start_line: u32,
    /// 1-indexed start column.
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    /// 1-indexed end line.
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// 1-indexed end column (exclusive).
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    /// Absolute byte offset from start of file.
    #[serde(rename = "byteOffset", skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u32>,
    /// Length of the region in bytes.
    #[serde(rename = "byteLength", skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<u32>,
    /// Optional inline snippet of the region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<ArtifactContent>,
}

/// Content embedded directly in a SARIF document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactContent {
    /// The textual content.
    pub text: String,
}

/// One auto-applicable fix proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fix {
    /// Description of what this fix does.
    pub description: Message,
    /// File-by-file edit set.
    #[serde(rename = "artifactChanges")]
    pub artifact_changes: Vec<ArtifactChange>,
}

/// All edits to one artifact (file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactChange {
    /// File being modified.
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    /// Atomic replacements.
    pub replacements: Vec<Replacement>,
}

/// One contiguous replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Replacement {
    /// Range to delete.
    #[serde(rename = "deletedRegion")]
    pub deleted_region: Region,
    /// Replacement content (None = pure deletion).
    #[serde(rename = "insertedContent", skip_serializing_if = "Option::is_none")]
    pub inserted_content: Option<ArtifactContent>,
}

/// Optional invocation metadata block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invocation {
    /// Whether the invocation succeeded.
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    /// Optional command line that produced this run.
    #[serde(rename = "commandLine", skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
}
