//! Kernel + probe-pack diagnostics for Clean Code V12.
//!
//! `cc-diagnostics` is **distinct from** `cc-finding`:
//!
//! | Crate            | Subject                       | Audience       |
//! |------------------|-------------------------------|----------------|
//! | `cc-finding`     | issues in **user code**       | end developer  |
//! | `cc-diagnostics` | issues in the **tool itself** | operator / CI  |
//!
//! Things that belong here: "rule X panicked", "probe-pack Y failed
//! to load", "config error in the repo", "frontend Z hit a parse-error
//! tree-sitter bug". This is what `--verbose` surfaces.
//!
//! # Phase 1 status
//!
//! Public traits + data types + a default no-op-ish [`TracingSink`]
//! plus a test-only [`CollectingSink`]. Concrete diagnostics emission
//! lands as the relevant subsystem comes online (Phase 2-5).
//!
//! ```ignore
//! use cc_diagnostics::{Diagnostic, DiagnosticSink, Level, Source, TracingSink};
//!
//! let sink = TracingSink::new();
//! sink.accept(Diagnostic::new(
//!     Level::Warn,
//!     "diag.probe.panic",
//!     Source::Probe,
//!     "rule `unused_import` panicked: index out of bounds; \
//!      please file a bug at github.com/LiquidLava1990/clean-code-v12/issues",
//! ));
//! ```
//!
//! # File map
//!
//! | Module        | Purpose                                          |
//! |---------------|--------------------------------------------------|
//! | `diagnostic`  | [`Diagnostic`] struct                            |
//! | `level`       | [`Level`] enum (Trace/Debug/Info/Warn/Error)     |
//! | `source`      | [`Source`] enum (Kernel/Frontend/Pack/Probe/...) |
//! | `sink`        | [`DiagnosticSink`] trait + ref impls             |
//! | `error`       | [`DiagnosticsError`]                             |

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod diagnostic;
pub mod error;
pub mod level;
pub mod sink;
pub mod source;

pub use diagnostic::Diagnostic;
pub use error::{DiagnosticsError, Result};
pub use level::Level;
pub use sink::{CollectingSink, DiagnosticSink, TracingSink};
pub use source::Source;

// TODO(phase-2): wire `TracingSink` as the default in `cc-cli` boot.
// TODO(phase-2): add `JsonlSink` for `--diagnostics-jsonl <path>` flag.
// TODO(phase-3): add rate-limiting wrapper sink so a flapping probe
//   cannot DOS operator log pipelines.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracing_sink_does_not_panic_on_each_level() {
        let sink = TracingSink::new();
        for level in [
            Level::Trace,
            Level::Debug,
            Level::Info,
            Level::Warn,
            Level::Error,
        ] {
            sink.accept(Diagnostic::new(
                level,
                "diag.test.smoke",
                Source::Kernel,
                "smoke",
            ));
        }
    }

    #[test]
    fn collecting_sink_accumulates_and_drains() {
        let sink = CollectingSink::new();
        assert!(sink.is_empty());

        sink.accept(Diagnostic::new(
            Level::Info,
            "diag.test.one",
            Source::Pack,
            "first",
        ));
        sink.accept(
            Diagnostic::new(Level::Warn, "diag.test.two", Source::Probe, "second")
                .with_probe_id("rule.unused_import"),
        );
        assert_eq!(sink.len(), 2);

        let snap = sink.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].code, "diag.test.one");
        assert_eq!(snap[1].probe_id.as_deref(), Some("rule.unused_import"));

        let drained = sink.drain();
        assert_eq!(drained.len(), 2);
        assert!(sink.is_empty());
    }

    #[test]
    fn diagnostic_builder_attaches_optional_fields() {
        let diag = Diagnostic::new(
            Level::Error,
            "diag.config.parse",
            Source::Config,
            "could not parse cc.toml at line 12; verify TOML syntax",
        )
        .with_location("cc.toml")
        .with_probe_id("loader");
        assert_eq!(
            diag.location.as_deref().map(camino::Utf8Path::as_str),
            Some("cc.toml")
        );
        assert_eq!(diag.probe_id.as_deref(), Some("loader"));
    }

    #[test]
    fn source_tag_is_lower_snake() {
        assert_eq!(Source::Kernel.tag(), "kernel");
        assert_eq!(Source::Other("custom_thing").tag(), "custom_thing");
    }

    #[test]
    fn error_messages_include_action() {
        let err = DiagnosticsError::InvalidCode {
            code: "BadCode".into(),
        };
        let s = err.to_string();
        assert!(s.contains("lower-snake-case"));
        assert!(s.contains("docs/diagnostics.md"));
    }
}
