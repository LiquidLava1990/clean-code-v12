//! [`Diagnostic`] — the kernel/pack equivalent of `cc_finding::Finding`,
//! but about the *tool* not the *user code*.

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};

use crate::level::Level;
use crate::source::Source;

/// A structured kernel/pack diagnostic.
///
/// Probe authors emit findings; the kernel and probe-packs emit
/// diagnostics. `--verbose` surfaces `Debug` and below; `--quiet` mutes
/// everything below [`Level::Warn`].
///
/// `code` is a dotted, lower-snake-case namespace (`diag.probe.panic`)
/// so dashboards can group on prefix without parsing free text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Operator-visibility level.
    pub level: Level,

    /// Stable diagnostic identifier (e.g. `"diag.probe.panic"`,
    /// `"diag.frontend.parse_error"`). Must be lower-snake-case dotted.
    pub code: &'static str,

    /// Human-readable, R-ERR-ACTION-shaped message: *what* + *how*.
    pub message: String,

    /// Optional file the diagnostic relates to (config path, probe
    /// pack root, source file the frontend choked on).
    pub location: Option<Utf8PathBuf>,

    /// Origin subsystem.
    pub source: Source,

    /// Probe identifier when `source` is [`Source::Pack`] or
    /// [`Source::Probe`]. `None` for kernel-internal diagnostics.
    pub probe_id: Option<String>,
}

impl Diagnostic {
    /// Construct a diagnostic with no location and no probe id —
    /// the common shape for kernel-internal diagnostics.
    #[must_use]
    pub fn new(
        level: Level,
        code: &'static str,
        source: Source,
        message: impl Into<String>,
    ) -> Self {
        Self {
            level,
            code,
            message: message.into(),
            location: None,
            source,
            probe_id: None,
        }
    }

    /// Builder-style location attach.
    #[must_use]
    pub fn with_location(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.location = Some(path.into());
        self
    }

    /// Builder-style probe-id attach.
    #[must_use]
    pub fn with_probe_id(mut self, probe_id: impl Into<String>) -> Self {
        self.probe_id = Some(probe_id.into());
        self
    }
}
