//! Atomic file I/O — write-to-temp + fsync + rename.
//!
//! Used by [`crate::repo::BaselineRepo::save`] so a kill-9 mid-write
//! never leaves a half-written baseline at the canonical path.

use std::fs::{File, OpenOptions};
use std::io::Write;

use camino::{Utf8Path, Utf8PathBuf};

use crate::error::{BaselineError, BaselineResult};

/// Sibling temp-file suffix used by [`atomic_write`].
const TMP_SUFFIX: &str = ".cc-baseline.tmp";

/// Atomically write `bytes` to `path`.
///
/// Strategy: write to `<path><TMP_SUFFIX>`, fsync, then rename over
/// `path`. Any failure leaves the original file untouched.
///
/// # Errors
/// Returns [`BaselineError::Write`] for create/write/fsync failures and
/// [`BaselineError::Rename`] when the final rename step fails.
pub fn atomic_write(path: &Utf8Path, bytes: &[u8]) -> BaselineResult<()> {
    let tmp = tmp_sibling(path);
    write_temp(&tmp, bytes)?;
    promote(&tmp, path)
}

/// Atomically write the byte stream produced by `body` to `path`.
///
/// This variant lets callers stream bytes through a custom [`Write`]
/// (e.g. an injected fault-injecting writer in tests) while still
/// keeping the temp-then-rename guarantee.
///
/// # Errors
/// Returns [`BaselineError::Write`] when `body` fails or fsync fails,
/// and [`BaselineError::Rename`] when the rename step fails.
pub fn atomic_write_with<F>(path: &Utf8Path, body: F) -> BaselineResult<()>
where
    F: FnOnce(&mut dyn Write) -> std::io::Result<()>,
{
    let tmp = tmp_sibling(path);
    {
        let mut file = create_temp_file(&tmp)?;
        body(&mut file).map_err(|source| BaselineError::Write {
            path: tmp.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| BaselineError::Write {
            path: tmp.clone(),
            source,
        })?;
    }
    promote(&tmp, path)
}

fn tmp_sibling(path: &Utf8Path) -> Utf8PathBuf {
    let mut tmp = path.to_path_buf();
    let file_name = tmp.file_name().unwrap_or("baseline").to_owned();
    tmp.set_file_name(format!("{file_name}{TMP_SUFFIX}"));
    tmp
}

fn write_temp(tmp: &Utf8Path, bytes: &[u8]) -> BaselineResult<()> {
    let mut file = create_temp_file(tmp)?;
    file.write_all(bytes)
        .map_err(|source| BaselineError::Write {
            path: tmp.to_path_buf(),
            source,
        })?;
    file.sync_all().map_err(|source| BaselineError::Write {
        path: tmp.to_path_buf(),
        source,
    })
}

fn create_temp_file(tmp: &Utf8Path) -> BaselineResult<File> {
    if let Some(parent) = tmp.parent() {
        if !parent.as_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| BaselineError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(tmp)
        .map_err(|source| BaselineError::Write {
            path: tmp.to_path_buf(),
            source,
        })
}

fn promote(tmp: &Utf8Path, path: &Utf8Path) -> BaselineResult<()> {
    std::fs::rename(tmp, path).map_err(|source| BaselineError::Rename {
        path: path.to_path_buf(),
        tmp: tmp.to_path_buf(),
        source,
    })
}
