//! [`RuntimeView`] — read-side trait probes consult to ground static
//! findings in observed cost.

use camino::Utf8Path;

use crate::cost::RuntimeCost;

/// Read-side query interface over an ingested profile.
///
/// Implementations MUST be `Send + Sync` so the kernel can share a
/// single `Arc<dyn RuntimeView>` across rayon worker threads.
///
/// All lookups return `None` when:
/// - no profile is loaded (use [`is_loaded`] to disambiguate);
/// - the file/function/line is not present in the loaded profile.
///
/// Probes interpret `None` as "no runtime witness — fall back to
/// static heuristic", never as "definitely cold".
///
/// [`is_loaded`]: RuntimeView::is_loaded
pub trait RuntimeView: Send + Sync {
    /// Cost of an entire function, addressed by file + qualified
    /// name (`module::path::function` for Rust, `pkg.Class.method`
    /// for Python, etc.).
    fn cost_for_function(&self, file: &Utf8Path, qualified_name: &str) -> Option<RuntimeCost>;

    /// Cost of a single call-site addressed by file + 1-based line
    /// number. Useful for hot-spot heuristics that fire at a
    /// specific call expression.
    fn cost_for_call_site(&self, file: &Utf8Path, line: u32) -> Option<RuntimeCost>;

    /// `true` when a profile has been ingested. `false` for the
    /// default [`EmptyRuntime`] and any view whose ingest failed.
    ///
    /// [`EmptyRuntime`]: crate::EmptyRuntime
    fn is_loaded(&self) -> bool;
}
