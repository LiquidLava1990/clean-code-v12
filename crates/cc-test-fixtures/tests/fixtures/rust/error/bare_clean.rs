//! Sample clean cc.error.bare: typed error with actionable message.

use std::fs;

#[derive(Debug, thiserror::Error)]
pub enum FixtureLoadError {
    /// Failure to read a fixture from disk.
    ///
    /// Recovery: confirm the path exists and is readable.
    #[error(
        "failed to read fixture path_kind={path_kind}; verify the path exists and is readable: {source}"
    )]
    Read {
        /// Stringified type of the offending path (no secret leak).
        path_kind: &'static str,
        /// Underlying io error.
        #[source]
        source: std::io::Error,
    },
}

pub fn safe_read(path: &str) -> Result<Vec<u8>, FixtureLoadError> {
    fs::read(path).map_err(|source| FixtureLoadError::Read {
        path_kind: "&str",
        source,
    })
}
