//! Runtime cost layer for Clean Code V12.
//!
//! Probes consult [`RuntimeView`] to ground static findings in
//! observed cost — *"this loop is in the top 1% of CPU time, so the
//! `quadratic_inner_loop` heuristic upgrades from `nit` to `required`"*.
//!
//! # Phase 4 status
//!
//! Three real ingest views landed alongside the no-op [`EmptyRuntime`]:
//! - [`PprofRuntime`] — Google pprof protobuf (raw or `.pb.gz`).
//! - [`OtlpRuntime`] — OpenTelemetry JSON trace export.
//! - [`MultiplexedRuntime`] — first-`Some` fan-out across views.
//!
//! ```ignore
//! use std::sync::Arc;
//! use camino::Utf8Path;
//! use cc_runtime::{MultiplexedRuntime, OtlpRuntime, PprofRuntime, RuntimeView};
//!
//! let mut mux = MultiplexedRuntime::empty();
//! mux.push(Arc::new(PprofRuntime::from_path(Utf8Path::new("cpu.pb.gz"))?));
//! mux.push(Arc::new(OtlpRuntime::from_path(Utf8Path::new("traces.json"))?));
//! let _ = mux.cost_for_function(Utf8Path::new("src/lib.rs"), "module::foo");
//! # Ok::<(), cc_runtime::RuntimeError>(())
//! ```
//!
//! # File map
//!
//! | Module        | Purpose                                       |
//! |---------------|-----------------------------------------------|
//! | `cost`        | [`RuntimeCost`], [`CpuTime`], [`Allocations`] |
//! | `query`       | [`RuntimeView`] trait                         |
//! | `empty`       | [`EmptyRuntime`] (no-op default)              |
//! | `error`       | [`RuntimeError`]                              |
//! | `pprof`       | [`PprofRuntime`] — pprof protobuf ingest      |
//! | `pprof_proto` | hand-written prost types for pprof v3         |
//! | `otlp`        | [`OtlpRuntime`] — OTLP/JSON ingest            |
//! | `multiplexed` | [`MultiplexedRuntime`] — fan-out view         |

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod cost;
pub mod empty;
pub mod error;
pub mod multiplexed;
pub mod otlp;
pub mod pprof;
mod pprof_proto;
pub mod query;

pub use cost::{Allocations, CpuTime, RuntimeCost};
pub use empty::EmptyRuntime;
pub use error::{Result, RuntimeError};
pub use multiplexed::MultiplexedRuntime;
pub use otlp::OtlpRuntime;
pub use pprof::PprofRuntime;
pub use query::RuntimeView;

// TODO(phase-5): streaming-ingest for >1GB profiles (chunked prost
//   decode + windowed aggregation).
// TODO(phase-5): collapsed-stack reader (Brendan Gregg / FlameGraph
//   format) — line-oriented, easier than pprof.
// TODO(phase-5): perfetto SQL ingest via the perfetto trace processor
//   shared library (Android/Chrome traces).
// TODO(phase-5): py-spy `--format=speedscope` + Scalene JSON adapters
//   so Python users without pprof support are first-class.
// TODO(phase-5): symbol resolver bridging language frontends → profile
//   symbols (Rust mangling vs Python qualname vs Go full path).

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8Path;

    #[test]
    fn empty_runtime_returns_none_everywhere() {
        let view = EmptyRuntime::new();
        assert!(!view.is_loaded());
        assert!(view
            .cost_for_function(Utf8Path::new("src/lib.rs"), "module::foo")
            .is_none());
        assert!(view
            .cost_for_call_site(Utf8Path::new("src/lib.rs"), 42)
            .is_none());
    }

    #[test]
    fn empty_runtime_is_object_safe() {
        let view: Box<dyn RuntimeView> = Box::new(EmptyRuntime::new());
        assert!(!view.is_loaded());
    }

    #[test]
    fn runtime_cost_observed_flag() {
        assert!(!RuntimeCost::default().is_observed());
        let cost = RuntimeCost::new(0.0, 0, 1, None);
        assert!(cost.is_observed());
    }

    #[test]
    fn error_messages_include_action() {
        let err = RuntimeError::UnsupportedFormat {
            path: "/tmp/x.bin".into(),
            detail: "magic bytes did not match pprof header".into(),
        };
        let s = err.to_string();
        assert!(s.contains("pprof"));
        assert!(s.contains("OTLP"));
    }
}
