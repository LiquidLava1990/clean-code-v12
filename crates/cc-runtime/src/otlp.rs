//! [`OtlpRuntime`] — OTLP/JSON trace ingest for [`RuntimeView`].
//!
//! Consumes the JSON shape produced by the OpenTelemetry JSON
//! exporter — the `traces-{timestamp}.json` files that ship with
//! every OTLP-aware language SDK. Tree shape:
//!
//! ```text
//! resourceSpans[]
//!   └─ scopeSpans[]
//!        └─ spans[]
//!             ├─ name: "module.fn"  (fallback function name)
//!             ├─ startTimeUnixNano / endTimeUnixNano
//!             └─ attributes[]
//!                  ├─ key: "code.function"   (semconv: function name)
//!                  └─ key: "code.filepath"   (semconv: source path)
//! ```
//!
//! Aggregates `(file_basename, function_name)` -> [`RuntimeCost`],
//! summing duration as CPU-seconds and incrementing `call_count`
//! per span.

use std::collections::BTreeMap;

use camino::Utf8Path;
use serde::Deserialize;

use crate::cost::RuntimeCost;
use crate::error::{Result, RuntimeError};
use crate::query::RuntimeView;

/// Ingested OTLP trace export, queryable as a [`RuntimeView`].
#[derive(Debug, Clone)]
pub struct OtlpRuntime {
    /// (`file_basename`, `function_name`) -> aggregated cost.
    by_function: BTreeMap<(String, String), RuntimeCost>,
}

impl OtlpRuntime {
    /// Read + parse an OTLP/JSON trace export from `path`.
    ///
    /// # Errors
    /// - [`RuntimeError::Io`] on read failure.
    /// - [`RuntimeError::OtlpDecode`] on malformed JSON.
    pub fn from_path(path: &Utf8Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|source| RuntimeError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_bytes(&bytes)
    }

    /// Parse OTLP/JSON bytes into a [`RuntimeView`].
    ///
    /// # Errors
    /// See [`Self::from_path`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let doc: OtlpDocument =
            serde_json::from_slice(bytes).map_err(|err| RuntimeError::OtlpDecode {
                detail: err.to_string(),
            })?;
        Ok(Self {
            by_function: aggregate_document(&doc),
        })
    }

    /// Total number of distinct (file, function) pairs ingested.
    /// Test-only helper.
    #[doc(hidden)]
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.by_function.len()
    }
}

impl RuntimeView for OtlpRuntime {
    fn cost_for_function(&self, file: &Utf8Path, qualified_name: &str) -> Option<RuntimeCost> {
        let basename = basename_of(file);
        for ((f, name), cost) in &self.by_function {
            if f != &basename {
                continue;
            }
            if name == qualified_name
                || qualified_name.ends_with(name)
                || name.ends_with(qualified_name)
            {
                return Some(*cost);
            }
        }
        None
    }

    fn cost_for_call_site(&self, _file: &Utf8Path, _line: u32) -> Option<RuntimeCost> {
        None
    }

    fn is_loaded(&self) -> bool {
        !self.by_function.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

fn aggregate_document(doc: &OtlpDocument) -> BTreeMap<(String, String), RuntimeCost> {
    let mut out: BTreeMap<(String, String), RuntimeCost> = BTreeMap::new();
    for resource in &doc.resource_spans {
        for scope in &resource.scope_spans {
            for span in &scope.spans {
                ingest_span(span, &mut out);
            }
        }
    }
    out
}

/// Project one OTLP span into the aggregation map.
fn ingest_span(span: &OtlpSpan, out: &mut BTreeMap<(String, String), RuntimeCost>) {
    let attrs = SpanAttrs::from_span(span);
    let function_name = attrs.function.clone().unwrap_or_else(|| span.name.clone());
    if function_name.is_empty() {
        return;
    }
    let file_basename = attrs.file_basename();
    let duration_ns = span.duration_nanos();

    let key = (file_basename, function_name);
    let entry = out.entry(key).or_default();
    if duration_ns > 0 {
        entry.cpu_seconds += nanos_to_seconds(duration_ns);
        // Keep p99 as the max observed per-call latency until we
        // gather enough samples for a real percentile.
        let ms = nanos_to_millis(duration_ns);
        entry.p99_latency_ms = Some(match entry.p99_latency_ms {
            Some(prev) if prev >= ms => prev,
            _ => ms,
        });
    }
    entry.call_count = entry.call_count.saturating_add(1);
}

#[allow(clippy::cast_precision_loss)]
fn nanos_to_seconds(nanos: u64) -> f64 {
    nanos as f64 / 1e9_f64
}

#[allow(clippy::cast_precision_loss)]
fn nanos_to_millis(nanos: u64) -> f64 {
    nanos as f64 / 1e6_f64
}

/// Resolved span attributes — subset we care about.
struct SpanAttrs {
    function: Option<String>,
    file: Option<String>,
}

impl SpanAttrs {
    fn from_span(span: &OtlpSpan) -> Self {
        let mut function = None;
        let mut file = None;
        for attr in &span.attributes {
            match attr.key.as_str() {
                "code.function" => function = attr.value.as_string(),
                "code.filepath" | "code.namespace" if file.is_none() => {
                    file = attr.value.as_string();
                }
                _ => {}
            }
        }
        Self { function, file }
    }

    fn file_basename(&self) -> String {
        self.file
            .as_deref()
            .map_or_else(String::new, |path| basename_of(Utf8Path::new(path)))
    }
}

/// `Utf8Path` -> file basename.
fn basename_of(path: &Utf8Path) -> String {
    path.file_name()
        .map_or_else(|| path.as_str().to_owned(), str::to_owned)
}

// ---------------------------------------------------------------------------
// OTLP/JSON schema (subset)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OtlpDocument {
    #[serde(default, rename = "resourceSpans")]
    resource_spans: Vec<OtlpResourceSpan>,
}

#[derive(Debug, Deserialize)]
struct OtlpResourceSpan {
    #[serde(default, rename = "scopeSpans")]
    scope_spans: Vec<OtlpScopeSpan>,
}

#[derive(Debug, Deserialize)]
struct OtlpScopeSpan {
    #[serde(default)]
    spans: Vec<OtlpSpan>,
}

#[derive(Debug, Deserialize)]
struct OtlpSpan {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "startTimeUnixNano")]
    start: NumericString,
    #[serde(default, rename = "endTimeUnixNano")]
    end: NumericString,
    #[serde(default)]
    attributes: Vec<OtlpAttribute>,
}

impl OtlpSpan {
    const fn duration_nanos(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }
}

#[derive(Debug, Deserialize)]
struct OtlpAttribute {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: OtlpAnyValue,
}

#[derive(Debug, Default, Deserialize)]
struct OtlpAnyValue {
    #[serde(default, rename = "stringValue")]
    string_value: Option<String>,
    #[serde(default, rename = "intValue")]
    int_value: Option<NumericString>,
}

impl OtlpAnyValue {
    fn as_string(&self) -> Option<String> {
        if let Some(s) = &self.string_value {
            return Some(s.clone());
        }
        self.int_value.as_ref().map(|n| n.0.to_string())
    }
}

/// OTLP encodes `int64` fields as JSON strings (per the proto3-JSON
/// rules: int64 ranges exceed JS Number precision). Accept either
/// strings or numbers for resilience.
#[derive(Debug, Default)]
struct NumericString(u64);

impl<'de> Deserialize<'de> for NumericString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = NumericString;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("integer or numeric string")
            }
            fn visit_u64<E: serde::de::Error>(
                self,
                v: u64,
            ) -> std::result::Result<NumericString, E> {
                Ok(NumericString(v))
            }
            fn visit_i64<E: serde::de::Error>(
                self,
                v: i64,
            ) -> std::result::Result<NumericString, E> {
                Ok(NumericString(u64::try_from(v).unwrap_or(0)))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<NumericString, E> {
                Ok(NumericString(v.parse().unwrap_or(0)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<NumericString, E> {
                self.visit_str(&v)
            }
        }
        deserializer.deserialize_any(V)
    }
}
