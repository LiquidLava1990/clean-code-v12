//! Output-format dispatch — turn an [`OutputFormat`] + optional output
//! file into a `Box<dyn FindingSink>` ready for the kernel.
//!
//! The four shipped formats:
//!
//! - [`OutputFormat::Tty`]    → `cc_finding::TtySink` (the default).
//! - [`OutputFormat::Sarif`]  → `cc_sarif::SarifSink`.
//! - [`OutputFormat::Rdjson`] → `cc_rdformat::RdJsonSink`.
//! - [`OutputFormat::Json`]   → [`JsonLinesSink`] (one Finding per line).
//!
//! Each sink owns a `Box<dyn Write + Send>` so output target (stdout vs.
//! file) is resolved once at construction.

use std::fs::File;
use std::io::{self, BufWriter, Write};

use camino::Utf8Path;
use cc_finding::{Finding, FindingError, FindingSink, Result as FindingResult, Summary, TtySink};
use cc_rdformat::RdJsonSink;
use cc_sarif::{to_sarif::ToolMeta, SarifSink};

use crate::args::OutputFormat;
use crate::error::CliError;

/// Build a sink for the requested format, writing to `output` if
/// supplied or to `stdout` otherwise.
///
/// # Errors
///
/// Returns [`CliError::OutputCreate`] when the requested file cannot be
/// created (parent missing, permission denied, etc.).
pub fn sink_for(
    format: OutputFormat,
    output: Option<&Utf8Path>,
) -> Result<Box<dyn FindingSink>, CliError> {
    let writer = build_writer(output)?;
    Ok(match format {
        OutputFormat::Tty => Box::new(TtySink::new(writer, supports_color(output))),
        OutputFormat::Sarif => Box::new(SarifSink::new(writer, ToolMeta::cc_kernel())),
        OutputFormat::Rdjson => Box::new(RdJsonSink::with_default_source(WriterBox(writer))),
        OutputFormat::Json => Box::new(JsonLinesSink::new(writer)),
    })
}

/// Resolve the writer target — buffered file when `output` is supplied,
/// buffered stdout otherwise.
fn build_writer(output: Option<&Utf8Path>) -> Result<Box<dyn Write + Send>, CliError> {
    let Some(path) = output else {
        return Ok(Box::new(BufWriter::new(io::stdout())));
    };
    ensure_output_parent_dir(path)?;
    let file = create_output_file(path)?;
    Ok(Box::new(BufWriter::new(file)))
}

/// Create any missing parent directory for `path`, mapping IO failures to
/// [`CliError::OutputCreate`]. Empty / root parents are a no-op.
fn ensure_output_parent_dir(path: &Utf8Path) -> Result<(), CliError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent.as_std_path()).map_err(|source| CliError::OutputCreate {
        path: path.to_path_buf(),
        source,
    })
}

/// Open `path` for write, mapping IO failures to [`CliError::OutputCreate`]
/// so the caller can surface the path that failed.
fn create_output_file(path: &Utf8Path) -> Result<File, CliError> {
    File::create(path.as_std_path()).map_err(|source| CliError::OutputCreate {
        path: path.to_path_buf(),
        source,
    })
}

/// Color-support heuristic: enable colour only when writing to a TTY
/// stdout (no `--output FILE`, no redirect).
const fn supports_color(output: Option<&Utf8Path>) -> bool {
    output.is_none()
}

/// Newtype over the boxed writer so it satisfies `RdJsonSink`'s generic
/// bounds (`W: Write + Send + 'static`).
struct WriterBox(Box<dyn Write + Send>);

impl std::fmt::Debug for WriterBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterBox").finish_non_exhaustive()
    }
}

impl Write for WriterBox {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }
}

/// Plain-JSON line-stream sink: one [`Finding`] serialised per line.
///
/// Distinct from `RdJsonSink` (which emits the reviewdog wire format)
/// and `SarifSink` (which buffers a single document). Useful for ad-hoc
/// piping to `jq` and language-agnostic CI integrations that don't yet
/// speak SARIF.
pub struct JsonLinesSink {
    writer: Box<dyn Write + Send>,
    summary: Summary,
}

impl std::fmt::Debug for JsonLinesSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonLinesSink")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl JsonLinesSink {
    /// Build a sink writing one JSON-encoded [`Finding`] per `\n`.
    #[must_use]
    pub fn new(writer: Box<dyn Write + Send>) -> Self {
        Self {
            writer,
            summary: Summary::new(),
        }
    }

    fn write_one(&mut self, finding: &Finding) -> FindingResult<()> {
        let line =
            serde_json::to_string(finding).map_err(|source| FindingError::Serde { source })?;
        self.writer
            .write_all(line.as_bytes())
            .and_then(|()| self.writer.write_all(b"\n"))
            .map_err(|source| FindingError::Io {
                context: "JsonLinesSink::emit",
                source,
            })?;
        Ok(())
    }
}

impl FindingSink for JsonLinesSink {
    fn emit(&mut self, finding: Finding) -> FindingResult<()> {
        self.write_one(&finding)?;
        self.summary.record(&finding);
        Ok(())
    }

    fn finish(mut self: Box<Self>) -> FindingResult<Summary> {
        self.writer.flush().map_err(|source| FindingError::Io {
            context: "JsonLinesSink::finish",
            source,
        })?;
        Ok(self.summary)
    }
}
