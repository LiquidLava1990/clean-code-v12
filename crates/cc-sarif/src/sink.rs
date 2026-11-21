//! Real [`SarifSink`] implementation — buffers Findings, writes one SARIF
//! document on `finish()`.

use std::io::Write;

use cc_finding::{
    error::{FindingError, Result as FindingResult},
    Finding, FindingSink, Summary,
};

use crate::error::SarifError;
use crate::to_sarif::{to_sarif, ToolMeta};

/// Output formatting mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Pretty-printed (newlines + 2-space indent). Human-readable default.
    Pretty,
    /// Compact (single line). Use under `--compact`.
    Compact,
}

/// SARIF sink — buffers findings, emits a single document on `finish()`.
///
/// Construct via [`SarifSink::new`]. The sink owns a boxed [`Write`] target
/// so the same type can write to a file, stdout, or an in-memory `Vec<u8>`.
pub struct SarifSink {
    writer: Box<dyn Write + Send>,
    tool_meta: ToolMeta,
    mode: OutputMode,
    buffer: Vec<Finding>,
    summary: Summary,
}

impl std::fmt::Debug for SarifSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SarifSink")
            .field("tool", &self.tool_meta.name)
            .field("version", &self.tool_meta.version)
            .field("mode", &self.mode)
            .field("buffered", &self.buffer.len())
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl SarifSink {
    /// Build a SARIF sink writing pretty JSON to the given target.
    #[must_use]
    pub fn new(writer: Box<dyn Write + Send>, tool_meta: ToolMeta) -> Self {
        Self {
            writer,
            tool_meta,
            mode: OutputMode::Pretty,
            buffer: Vec::new(),
            summary: Summary::new(),
        }
    }

    /// Switch to compact (single-line) output.
    #[must_use]
    pub const fn compact(mut self) -> Self {
        self.mode = OutputMode::Compact;
        self
    }

    /// Number of buffered findings (debug aid).
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Write the buffered findings as a SARIF document.
    ///
    /// # Errors
    /// Surfaces serde + I/O failures from the configured writer.
    pub fn write_document(&mut self) -> Result<(), SarifError> {
        let doc = to_sarif(&self.buffer, self.tool_meta);
        match self.mode {
            OutputMode::Pretty => serde_json::to_writer_pretty(&mut self.writer, &doc)?,
            OutputMode::Compact => serde_json::to_writer(&mut self.writer, &doc)?,
        }
        self.writer
            .write_all(b"\n")
            .map_err(|source| SarifError::Io {
                context: "SarifSink::write_document trailing newline",
                source,
            })?;
        self.writer.flush().map_err(|source| SarifError::Io {
            context: "SarifSink::write_document flush",
            source,
        })?;
        Ok(())
    }
}

impl FindingSink for SarifSink {
    fn emit(&mut self, finding: Finding) -> FindingResult<()> {
        self.summary.record(&finding);
        self.buffer.push(finding);
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> FindingResult<Summary> {
        self.write_document().map_err(into_finding_error)?;
        Ok(self.summary)
    }
}

fn into_finding_error(err: SarifError) -> FindingError {
    match err {
        SarifError::Serde { source } => FindingError::Serde { source },
        SarifError::Io { context, source } => FindingError::Io { context, source },
        SarifError::Validation { count, .. } => FindingError::InvalidValue {
            field: "sarif_document",
            reason: format!(
                "self-validation failed with {count} issue(s); \
                 fix the upstream Finding(s) and re-emit"
            ),
        },
    }
}
