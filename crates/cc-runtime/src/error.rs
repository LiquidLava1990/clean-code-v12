//! Errors emitted by `cc-runtime`.
//!
//! Every variant follows R-ERR-ACTION: it states *what* went wrong
//! and *how* to fix it.

use camino::Utf8PathBuf;
use thiserror::Error;

/// Errors raised when ingesting or querying a runtime profile.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The profile file could not be opened/read.
    #[error(
        "could not read runtime profile `{path}`: {source}; \
         verify the path exists and the kernel has read permission"
    )]
    Io {
        /// Profile path that failed to open.
        path: Utf8PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The profile format was unrecognised.
    #[error(
        "unsupported runtime profile format at `{path}`: {detail}; \
         use pprof (.pb.gz), OTLP (.json), or collapsed-stack (.txt)"
    )]
    UnsupportedFormat {
        /// Profile path.
        path: Utf8PathBuf,
        /// What about the format failed (header bytes, extension, etc).
        detail: String,
    },

    /// The profile parsed but referenced symbols not found in the
    /// current source tree.
    #[error(
        "runtime profile at `{path}` references unknown symbol `{symbol}`; \
         re-run the profiler against the same revision the kernel is analysing"
    )]
    SymbolMismatch {
        /// Profile path.
        path: Utf8PathBuf,
        /// The unresolved symbol.
        symbol: String,
    },

    /// A pprof protobuf payload was malformed.
    #[error(
        "pprof payload could not be decoded: {detail}; \
         verify the file was produced by a Google pprof-compatible \
         profiler (Go runtime/pprof, gperftools, py-spy --format=pprof, fgprof)"
    )]
    PprofDecode {
        /// What about the payload failed (varint, missing message, etc).
        detail: String,
    },

    /// Gzip decompression failed for a `.pb.gz` payload.
    #[error(
        "gzip decompression failed: {detail}; \
         verify the profile file is not truncated and is a valid \
         gzip stream produced by the profiler"
    )]
    Gzip {
        /// Underlying decompression error message.
        detail: String,
    },

    /// An OTLP JSON document could not be parsed.
    #[error(
        "OTLP JSON could not be parsed: {detail}; \
         verify the file is the JSON-formatted output of an OTLP \
         exporter (resourceSpans → scopeSpans → spans tree)"
    )]
    OtlpDecode {
        /// Underlying `serde_json` error message.
        detail: String,
    },
}

/// Crate-wide convenience [`Result`] alias.
pub type Result<T> = std::result::Result<T, RuntimeError>;
