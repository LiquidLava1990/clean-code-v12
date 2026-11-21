//! `cc_check` tool implementation.
//!
//! Two input shapes (mutually exclusive):
//!
//! 1. `{ "path": "<dir or file>" }` — scan a real on-disk path.
//! 2. `{ "content": "<source>", "language": "<lang>" }` — write the
//!    snippet to a temp dir under a synthetic filename so the kernel's
//!    extension dispatcher routes it to the right frontend, then scan
//!    that temp dir.
//!
//! In both cases we re-use the kernel's `with_default_packs` registry
//! and produce a `Vec<Finding>` (serialised as JSON for the MCP
//! response).

use std::fs;
use std::path::Path;

use camino::{Utf8Path, Utf8PathBuf};
use cc_config::Config;
use cc_finding::Finding;
use cc_kernel::Kernel;

/// Implement the `cc_check` tool.
///
/// # Errors
///
/// Returns `Err(message)` for argument validation failures, IO errors
/// while staging an inline snippet, or kernel runtime errors. The
/// message is surfaced to the model via the MCP tool-error envelope.
pub fn run_cc_check(args: &serde_json::Value) -> Result<serde_json::Value, String> {
    let scan = build_scan_target(args)?;
    let findings = scan_target(&scan.root)?;
    drop(scan); // ensure tempdir lives until after scan
    Ok(serde_json::json!({
        "count": findings.len(),
        "findings": findings,
    }))
}

/// Encapsulates a directory the kernel can scan.
///
/// Holds an optional `tempfile::TempDir` so inline-content scans clean
/// up automatically when the result is built.
struct ScanTarget {
    root: Utf8PathBuf,
    _tempdir: Option<tempfile::TempDir>,
}

fn build_scan_target(args: &serde_json::Value) -> Result<ScanTarget, String> {
    let path = args.get("path").and_then(|v| v.as_str());
    let content = args.get("content").and_then(|v| v.as_str());
    let language = args.get("language").and_then(|v| v.as_str());
    match (path, content, language) {
        (Some(p), None, None) => target_from_path(p),
        (None, Some(c), Some(lang)) => target_from_content(c, lang),
        (Some(_), Some(_), _) => Err(
            "pass either `path` OR `content`+`language`, not both. Fix: drop the unused field."
                .to_owned(),
        ),
        (None, Some(_), None) => Err(
            "`content` requires `language`. Fix: add e.g. `\"language\":\"python\"`.".to_owned(),
        ),
        _ => Err(
            "missing args. Fix: pass `{\"path\":\"...\"}` or `{\"content\":\"...\",\"language\":\"python\"}`."
                .to_owned(),
        ),
    }
}

fn target_from_path(path: &str) -> Result<ScanTarget, String> {
    let p = Path::new(path);
    let absolute = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| format!("cannot resolve cwd: {err}"))?
            .join(p)
    };
    if !absolute.exists() {
        return Err(format!(
            "path `{}` does not exist. Fix: pass an existing file or directory.",
            absolute.display(),
        ));
    }
    let root = if absolute.is_dir() {
        absolute
    } else {
        absolute
            .parent()
            .ok_or_else(|| "file has no parent directory".to_owned())?
            .to_path_buf()
    };
    let utf8 = Utf8PathBuf::from_path_buf(root)
        .map_err(|bad| format!("path `{}` is not valid UTF-8", bad.display()))?;
    Ok(ScanTarget {
        root: utf8,
        _tempdir: None,
    })
}

fn target_from_content(content: &str, language: &str) -> Result<ScanTarget, String> {
    let extension = extension_for_language(language)?;
    let tempdir = tempfile::tempdir().map_err(|err| format!("cannot create temp dir: {err}"))?;
    let file = tempdir.path().join(format!("snippet.{extension}"));
    fs::write(&file, content)
        .map_err(|err| format!("cannot write snippet to `{}`: {err}", file.display(),))?;
    let utf8_root = Utf8PathBuf::from_path_buf(tempdir.path().to_path_buf())
        .map_err(|bad| format!("temp dir `{}` is not valid UTF-8", bad.display()))?;
    Ok(ScanTarget {
        root: utf8_root,
        _tempdir: Some(tempdir),
    })
}

fn extension_for_language(language: &str) -> Result<&'static str, String> {
    match language.to_ascii_lowercase().as_str() {
        "python" | "py" => Ok("py"),
        "typescript" | "ts" => Ok("ts"),
        "javascript" | "js" => Ok("js"),
        "go" => Ok("go"),
        "rust" | "rs" => Ok("rs"),
        other => Err(format!(
            "unsupported language `{other}`. Fix: use python, typescript, javascript, go, or rust.",
        )),
    }
}

fn scan_target(root: &Utf8Path) -> Result<Vec<Finding>, String> {
    let config = Config::default_for_repo(root);
    let mut kernel =
        Kernel::new(config).map_err(|err| format!("kernel construction failed: {err}"))?;
    kernel
        .with_default_packs()
        .map_err(|err| format!("default pack registration failed: {err}"))?;
    let report = kernel
        .run(root)
        .map_err(|err| format!("kernel run failed: {err}"))?;
    Ok(report.findings)
}
