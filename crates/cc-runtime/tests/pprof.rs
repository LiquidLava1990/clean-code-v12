//! Integration tests for [`PprofRuntime`].

use std::io::Write as _;

use camino::Utf8Path;
use cc_runtime::pprof::build_synthetic_pprof_bytes;
use cc_runtime::{PprofRuntime, RuntimeView};
use flate2::write::GzEncoder;
use flate2::Compression;

/// One synthetic stack frame round-trips through the parser.
#[test]
fn pprof_round_trip_synthetic() {
    let bytes = build_synthetic_pprof_bytes("src/foo.rs", "module::hot_loop", 1_500_000_000, 4_096);
    let view = PprofRuntime::from_bytes(&bytes).expect("synthetic profile parses");

    assert!(view.is_loaded());
    assert_eq!(view.entry_count(), 1);

    let cost = view
        .cost_for_function(Utf8Path::new("src/foo.rs"), "module::hot_loop")
        .expect("recorded function resolves");
    assert!((cost.cpu_seconds - 1.5).abs() < 1e-6);
    assert_eq!(cost.allocations_bytes, 4_096);
    assert!(cost.call_count >= 1);
}

/// Gzipped (`.pb.gz`) profiles transparently decompress.
#[test]
fn pprof_handles_gzipped() {
    let raw = build_synthetic_pprof_bytes("src/bar.rs", "module::warm_path", 250_000_000, 0);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&raw).expect("gzip write");
    let gzipped = encoder.finish().expect("gzip finish");

    let view = PprofRuntime::from_bytes(&gzipped).expect("gzipped synthetic profile parses");
    let cost = view
        .cost_for_function(Utf8Path::new("src/bar.rs"), "module::warm_path")
        .expect("function present after gunzip");
    assert!((cost.cpu_seconds - 0.25).abs() < 1e-6);
}

/// Function names absent from the profile yield `None` (not zero).
#[test]
fn pprof_unknown_function_returns_none() {
    let bytes = build_synthetic_pprof_bytes("src/baz.rs", "module::known", 100_000_000, 0);
    let view = PprofRuntime::from_bytes(&bytes).expect("synthetic parses");

    assert!(view
        .cost_for_function(Utf8Path::new("src/baz.rs"), "module::not_in_profile")
        .is_none());
    // Wrong file basename also misses, even with matching name.
    assert!(view
        .cost_for_function(Utf8Path::new("src/other.rs"), "module::known")
        .is_none());
}

/// Suffix-tolerant matching handles import-path differences.
#[test]
fn pprof_suffix_match_handles_import_paths() {
    let bytes = build_synthetic_pprof_bytes("svc.py", "service.handler", 100_000_000, 0);
    let view = PprofRuntime::from_bytes(&bytes).expect("synthetic parses");

    // Probe carries the fully-qualified module path; profile only
    // recorded the trailing two segments.
    let cost = view
        .cost_for_function(Utf8Path::new("svc.py"), "app.api.service.handler")
        .expect("suffix match resolves");
    assert!(cost.cpu_seconds > 0.0);
}
