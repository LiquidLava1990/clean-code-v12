//! Streaming [`RdJsonSink`] — writes one JSON object per line.
//!
//! Replaces the stub of the same name in `cc-finding`. The stub stays
//! published from `cc-finding` so downstream crates can wire trait
//! objects without circular dependencies; this real implementation is
//! the one used by binaries.

use std::io::{self, Write};

use cc_finding::{Finding, FindingError, FindingSink, Result as FindingResult, Summary};

use crate::doc::SourceMeta;
use crate::error::RdFormatError;
use crate::to_rdjson::to_rdjson;

/// Streaming `RDJSON` sink — writes one JSON object per line.
///
/// `RDJSON` is line-delimited (NDJSON): every [`Finding`] becomes one
/// `\n`-terminated JSON object. The sink is generic over any
/// [`io::Write`] target, so callers can route to a file, a pipe to
/// `reviewdog`, or an in-memory `Vec<u8>` for tests.
pub struct RdJsonSink<W: Write + Send> {
    writer: W,
    source_meta: SourceMeta,
    summary: Summary,
}

impl<W: Write + Send + std::fmt::Debug> std::fmt::Debug for RdJsonSink<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdJsonSink")
            .field("writer", &self.writer)
            .field("source_meta", &self.source_meta)
            .field("summary", &self.summary)
            .finish()
    }
}

impl<W: Write + Send> RdJsonSink<W> {
    /// Construct a sink writing to `writer` and tagging diagnostics with
    /// `source_meta`.
    pub fn new(writer: W, source_meta: SourceMeta) -> Self {
        Self {
            writer,
            source_meta,
            summary: Summary::new(),
        }
    }

    /// Convenience wrapper using [`SourceMeta::clean_code_v12`].
    pub fn with_default_source(writer: W) -> Self {
        Self::new(writer, SourceMeta::clean_code_v12())
    }

    /// Borrow the configured tool identity.
    pub const fn source_meta(&self) -> &SourceMeta {
        &self.source_meta
    }

    /// Borrow the running summary (post-emit counters).
    pub const fn summary(&self) -> &Summary {
        &self.summary
    }

    /// Consume the sink and return the underlying writer (handy for
    /// tests that target an in-memory buffer).
    pub fn into_writer(self) -> W {
        self.writer
    }

    /// Serialise + write one finding as a single `\n`-terminated line.
    fn write_one(&mut self, finding: &Finding) -> Result<(), RdFormatError> {
        let diag = to_rdjson(finding, self.source_meta);
        let line = serde_json::to_string(&diag)?;
        self.writer
            .write_all(line.as_bytes())
            .and_then(|()| self.writer.write_all(b"\n"))
            .map_err(|source| RdFormatError::Io {
                context: "RdJsonSink::emit",
                source,
            })?;
        Ok(())
    }
}

impl RdJsonSink<io::Stdout> {
    /// Build a sink writing to stdout with the default Clean-Code-V12
    /// source identity.
    #[must_use]
    pub fn stdout() -> Self {
        Self::with_default_source(io::stdout())
    }
}

impl<W: Write + Send + 'static> FindingSink for RdJsonSink<W> {
    fn emit(&mut self, finding: Finding) -> FindingResult<()> {
        self.write_one(&finding).map_err(FindingError::from)?;
        self.summary.record(&finding);
        Ok(())
    }

    fn finish(self: Box<Self>) -> FindingResult<Summary> {
        let mut writer = self.writer;
        writer.flush().map_err(|source| FindingError::Io {
            context: "RdJsonSink::finish",
            source,
        })?;
        Ok(self.summary)
    }
}

#[cfg(test)]
#[path = "sink_tests.rs"]
mod tests;
