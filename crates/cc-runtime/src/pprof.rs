//! [`PprofRuntime`] — pprof protobuf ingest for [`RuntimeView`].
//!
//! Accepts the canonical Google pprof `Profile` message as either
//! raw protobuf bytes or a gzipped (`.pb.gz`) payload. Aggregates
//! per-function CPU samples + allocation bytes by walking every
//! sample's stack and crediting all visited frames.
//!
//! # Aggregation key
//!
//! `(file_basename, function_name)`. The file basename strips
//! directory prefix so a probe holding `src/foo.rs` matches a
//! profile recorded with the absolute build path `/build/src/foo.rs`.
//!
//! # Lookup resilience
//!
//! [`RuntimeView::cost_for_function`] succeeds when the *file
//! basename matches* AND *the recorded function name is a suffix of
//! the requested qualified name* (or vice-versa). This handles
//! import-path differences between static analysis and the profiler
//! — e.g. Python's `pkg.module.fn` vs pprof's `module.fn`.

use std::collections::BTreeMap;
use std::io::Read as _;

use camino::{Utf8Path, Utf8PathBuf};
use flate2::read::GzDecoder;
use prost::Message as _;

use crate::cost::RuntimeCost;
use crate::error::{Result, RuntimeError};
use crate::pprof_proto::Profile;
use crate::query::RuntimeView;

/// Ingested pprof profile, queryable as a [`RuntimeView`].
#[derive(Debug, Clone)]
pub struct PprofRuntime {
    /// (`file_basename`, `function_name`) -> aggregated cost.
    by_function: BTreeMap<(String, String), RuntimeCost>,
}

impl PprofRuntime {
    /// Read + decode a pprof profile from `path`. Detects gzip by
    /// the standard magic header (`1f 8b`).
    ///
    /// # Errors
    /// - [`RuntimeError::Io`] on read failure.
    /// - [`RuntimeError::Gzip`] on bad gzip stream.
    /// - [`RuntimeError::PprofDecode`] on malformed protobuf.
    pub fn from_path(path: &Utf8Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|source| RuntimeError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_bytes(&bytes)
    }

    /// Decode pprof bytes (raw protobuf or gzip-wrapped) into a view.
    ///
    /// # Errors
    /// See [`Self::from_path`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let payload = decode_payload(bytes)?;
        let profile =
            Profile::decode(payload.as_slice()).map_err(|err| RuntimeError::PprofDecode {
                detail: format!("prost decode failed: {err}"),
            })?;
        Ok(Self {
            by_function: aggregate_profile(&profile),
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

impl RuntimeView for PprofRuntime {
    fn cost_for_function(&self, file: &Utf8Path, qualified_name: &str) -> Option<RuntimeCost> {
        let basename = basename_of(file);
        for ((f, name), cost) in &self.by_function {
            if f != &basename {
                continue;
            }
            if name_matches(qualified_name, name) {
                return Some(*cost);
            }
        }
        None
    }

    fn cost_for_call_site(&self, _file: &Utf8Path, _line: u32) -> Option<RuntimeCost> {
        // pprof aggregates by function/location IDs; per-line
        // grouping is left for a future revision.
        None
    }

    fn is_loaded(&self) -> bool {
        !self.by_function.is_empty()
    }
}

/// Detect gzip magic + decompress; otherwise return owned copy.
fn decode_payload(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        let mut decoder = GzDecoder::new(bytes);
        let mut out = Vec::with_capacity(bytes.len() * 4);
        decoder
            .read_to_end(&mut out)
            .map_err(|err| RuntimeError::Gzip {
                detail: err.to_string(),
            })?;
        return Ok(out);
    }
    Ok(bytes.to_vec())
}

/// Walk every sample, crediting each visited frame with the sample's
/// cpu / alloc values (sample types matched by name).
fn aggregate_profile(profile: &Profile) -> BTreeMap<(String, String), RuntimeCost> {
    let mut out: BTreeMap<(String, String), RuntimeCost> = BTreeMap::new();
    let value_index = ValueIndex::from_profile(profile);

    for sample in &profile.sample {
        let cpu_ns = value_index.column_value(&sample.value, value_index.cpu);
        let alloc_bytes = value_index.column_value(&sample.value, value_index.alloc);
        let count_value = value_index.column_value(&sample.value, value_index.count);

        let sample_costs = SampleCosts {
            cpu_ns,
            alloc_bytes,
            count_value,
        };
        for &loc_id in &sample.location_id {
            let Some(loc) = profile.location.iter().find(|l| l.id == loc_id) else {
                continue;
            };
            for line in &loc.line {
                credit_frame(CreditFrameInputs {
                    profile,
                    out: &mut out,
                    function_id: line.function_id,
                    costs: sample_costs,
                });
            }
        }
    }
    out
}

/// Per-sample cost columns picked from the pprof value vector.
#[derive(Debug, Clone, Copy)]
struct SampleCosts {
    cpu_ns: i64,
    alloc_bytes: i64,
    count_value: i64,
}

/// Inputs to [`credit_frame`] — grouped to keep parameter count low and
/// to clarify the relationship between the mutable accumulator and the
/// per-frame metadata.
struct CreditFrameInputs<'a> {
    profile: &'a Profile,
    out: &'a mut BTreeMap<(String, String), RuntimeCost>,
    function_id: u64,
    costs: SampleCosts,
}

/// Update the (file, function) bucket with one frame's contribution.
fn credit_frame(inputs: CreditFrameInputs<'_>) {
    let CreditFrameInputs {
        profile,
        out,
        function_id,
        costs,
    } = inputs;
    let Some(func) = profile.function.iter().find(|f| f.id == function_id) else {
        return;
    };
    let name = lookup_string(profile, func.name);
    if name.is_empty() {
        return;
    }
    let filename = lookup_string(profile, func.filename);
    let entry = out.entry((basename_str(&filename), name)).or_default();
    apply_costs(entry, costs);
}

/// Fold one frame's [`SampleCosts`] into a [`RuntimeCost`] accumulator.
fn apply_costs(entry: &mut RuntimeCost, costs: SampleCosts) {
    if costs.cpu_ns > 0 {
        entry.cpu_seconds += nanos_to_seconds(as_nonnegative(costs.cpu_ns));
    }
    if costs.alloc_bytes > 0 {
        entry.allocations_bytes = entry
            .allocations_bytes
            .saturating_add(as_nonnegative(costs.alloc_bytes));
    }
    let count_inc = if costs.count_value > 0 {
        as_nonnegative(costs.count_value)
    } else {
        1
    };
    entry.call_count = entry.call_count.saturating_add(count_inc);
}

/// Convert nanoseconds to floating-point seconds. Loss of precision
/// above 2^52 ns (~52 days) is acceptable for profile aggregates.
#[allow(clippy::cast_precision_loss)]
fn nanos_to_seconds(nanos: u64) -> f64 {
    nanos as f64 / 1e9_f64
}

/// Saturating cast `i64 -> u64` for non-negative inputs.
fn as_nonnegative(value: i64) -> u64 {
    if value < 0 {
        0
    } else {
        u64::try_from(value).unwrap_or(0)
    }
}

/// Resolve a string-table index, returning `""` if out of range.
fn lookup_string(profile: &Profile, idx: i64) -> String {
    if idx < 0 {
        return String::new();
    }
    let Ok(i) = usize::try_from(idx) else {
        return String::new();
    };
    profile.string_table.get(i).cloned().unwrap_or_default()
}

/// Resolve which sample-value columns hold cpu / alloc / count data.
struct ValueIndex {
    cpu: Option<usize>,
    alloc: Option<usize>,
    count: Option<usize>,
}

impl ValueIndex {
    fn from_profile(profile: &Profile) -> Self {
        let mut idx = Self {
            cpu: None,
            alloc: None,
            count: None,
        };
        for (i, st) in profile.sample_type.iter().enumerate() {
            let kind = lookup_string(profile, st.r#type);
            idx.classify(i, &kind);
        }
        idx
    }

    fn classify(&mut self, position: usize, kind: &str) {
        match kind {
            "cpu" | "samples" if self.cpu.is_none() => self.cpu = Some(position),
            "alloc_space" | "alloc_objects" | "inuse_space" if self.alloc.is_none() => {
                self.alloc = Some(position);
            }
            "samples" if self.count.is_none() => self.count = Some(position),
            _ => {}
        }
    }

    #[allow(clippy::unused_self)] // Logical association with ValueIndex.
    fn column_value(&self, values: &[i64], column: Option<usize>) -> i64 {
        column.and_then(|i| values.get(i).copied()).unwrap_or(0)
    }
}

/// `Utf8Path` -> file basename (`"foo.rs"`).
fn basename_of(path: &Utf8Path) -> String {
    path.file_name()
        .map_or_else(|| path.as_str().to_owned(), str::to_owned)
}

/// String-form basename helper for raw filename strings.
pub(crate) fn basename_str(filename: &str) -> String {
    let path = Utf8PathBuf::from(filename);
    basename_of(&path)
}

/// Suffix-tolerant function-name match.
///
/// Equality wins. Otherwise, treat both names as `::` / `.` separated
/// and accept when one is the trailing suffix of the other. This
/// lets `pkg.module.fn` (pprof) match `module.fn` (probe) and
/// vice-versa.
fn name_matches(probe_name: &str, recorded: &str) -> bool {
    if probe_name == recorded {
        return true;
    }
    if probe_name.ends_with(recorded) || recorded.ends_with(probe_name) {
        return boundary_aligned(probe_name, recorded);
    }
    false
}

/// True when one name's suffix start aligns with a `::` / `.` boundary
/// in the other (avoid `foobar` matching `bar`).
fn boundary_aligned(a: &str, b: &str) -> bool {
    let (long, short) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    if long == short {
        return true;
    }
    let split = long.len() - short.len();
    matches!(
        long.as_bytes().get(split.saturating_sub(1)),
        Some(b'.' | b':')
    )
}

// ---------------------------------------------------------------------------
// Test-only fixture builder. Lives here so integration tests don't
// need access to the private `pprof_proto` module.
// ---------------------------------------------------------------------------

/// Build synthetic pprof bytes for a single function/file pair with
/// the given CPU nanos + alloc bytes. **Test-only**; the encoded
/// payload mirrors what `runtime/pprof` produces for one stack-frame
/// sample.
///
/// Returns the raw protobuf bytes (un-gzipped). Used by
/// `tests/pprof.rs`.
#[doc(hidden)]
#[must_use]
pub fn build_synthetic_pprof_bytes(
    file: &str,
    function: &str,
    cpu_nanos: i64,
    alloc_bytes: i64,
) -> Vec<u8> {
    let profile = synthetic_profile(file, function, cpu_nanos, alloc_bytes);
    encode_profile(&profile)
}

fn synthetic_profile(file: &str, function: &str, cpu_nanos: i64, alloc_bytes: i64) -> Profile {
    use crate::pprof_proto::{Function as PFunction, Line, Location, Mapping, Sample, ValueType};

    // String table: [0]="" (mandatory), [1]="cpu", [2]="nanoseconds",
    // [3]="alloc_space", [4]="bytes", [5]=function, [6]=file.
    let strings = vec![
        String::new(),
        "cpu".to_owned(),
        "nanoseconds".to_owned(),
        "alloc_space".to_owned(),
        "bytes".to_owned(),
        function.to_owned(),
        file.to_owned(),
    ];

    Profile {
        sample_type: vec![
            ValueType { r#type: 1, unit: 2 },
            ValueType { r#type: 3, unit: 4 },
        ],
        sample: vec![Sample {
            location_id: vec![1],
            value: vec![cpu_nanos, alloc_bytes],
        }],
        mapping: vec![Mapping {
            id: 1,
            memory_start: 0,
            memory_limit: 0,
            file_offset: 0,
            filename: 6,
        }],
        location: vec![Location {
            id: 1,
            mapping_id: 1,
            address: 0,
            line: vec![Line {
                function_id: 1,
                line: 1,
            }],
        }],
        function: vec![PFunction {
            id: 1,
            name: 5,
            system_name: 5,
            filename: 6,
            start_line: 1,
        }],
        string_table: strings,
    }
}

fn encode_profile(profile: &Profile) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    // `prost::Message::encode` only fails on insufficient buffer
    // capacity; `Vec` grows on demand, so the branch is unreachable.
    // We still propagate via `Result::ok` to comply with the
    // no-`expect` rule outside tests.
    if profile.encode(&mut out).is_err() {
        out.clear();
    }
    out
}
