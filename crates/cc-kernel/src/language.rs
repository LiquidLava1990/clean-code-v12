//! Extension → [`LanguageFrontend`] dispatch.
//!
//! The kernel walks the repo and, for every file with a known
//! extension, asks this module for the right frontend. Unknown
//! extensions return `None` and the file is recorded as skipped.
//!
//! The four shipped frontends are zero-sized; constructing one is free,
//! and they all implement `Send + Sync` so the parallel parse-lift fan
//! out is safe.

use camino::Utf8Path;
use cc_frontend::LanguageFrontend;
use cc_frontend_go::GoFrontend;
use cc_frontend_python::PythonFrontend;
use cc_frontend_rust::RustFrontend;
use cc_frontend_typescript::{is_tsx_extension, TypescriptFrontend};

/// Resolve a language frontend for a given path's extension.
///
/// Returns `None` when the extension is unknown — the kernel records
/// such files as skipped without surfacing an error.
///
/// `.tsx` / `.jsx` route to [`TypescriptFrontend`] like all the other
/// JS/TS extensions; the frontend selects the TSX grammar internally
/// via [`TypescriptFrontend::parse_tsx`] when the file extension
/// requires it. Phase 1 tooling routes plain TS/JS through [`TypescriptFrontend::parse`];
/// TSX-aware parsing is a follow-up once the kernel passes per-file
/// extension hints into the lift call.
#[must_use]
pub fn frontend_for_path(path: &Utf8Path) -> Option<Box<dyn LanguageFrontend>> {
    let ext = path.extension()?.to_ascii_lowercase();
    match ext.as_str() {
        "py" | "pyi" => Some(Box::new(PythonFrontend::new())),
        "ts" | "mts" | "cts" | "js" | "mjs" | "cjs" | "tsx" | "jsx" => {
            Some(Box::new(TypescriptFrontend::new()))
        }
        "go" => Some(Box::new(GoFrontend::new())),
        "rs" => Some(Box::new(RustFrontend::new())),
        _ => None,
    }
}

/// True iff the given path extension is one the kernel knows how to
/// parse + lift. Mirrors [`frontend_for_path`] without allocating a
/// boxed frontend.
#[must_use]
pub fn is_supported_extension(path: &Utf8Path) -> bool {
    path.extension()
        .map(str::to_ascii_lowercase)
        .is_some_and(|ext| {
            matches!(
                ext.as_str(),
                "py" | "pyi"
                    | "ts"
                    | "mts"
                    | "cts"
                    | "js"
                    | "mjs"
                    | "cjs"
                    | "tsx"
                    | "jsx"
                    | "go"
                    | "rs"
            )
        })
}

/// True iff the given extension routes to the TSX grammar variant.
///
/// Re-exported convenience wrapper around `cc_frontend_typescript::is_tsx_extension`.
#[must_use]
pub fn extension_is_tsx(extension: &str) -> bool {
    is_tsx_extension(extension)
}
