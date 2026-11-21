//! [`EmptyRuntime`] — the no-profile default [`RuntimeView`].
//!
//! Wired at boot when no `--runtime-profile` flag is supplied. Every
//! lookup returns `None` and [`is_loaded`] returns `false`, so probes
//! transparently fall back to their static-only heuristic.
//!
//! [`is_loaded`]: crate::RuntimeView::is_loaded

use camino::Utf8Path;

use crate::cost::RuntimeCost;
use crate::query::RuntimeView;

/// Default zero-witness [`RuntimeView`].
///
/// Trivially cheap to construct; no allocation, no I/O.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyRuntime;

impl EmptyRuntime {
    /// Construct an empty runtime view.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl RuntimeView for EmptyRuntime {
    fn cost_for_function(&self, _file: &Utf8Path, _qualified_name: &str) -> Option<RuntimeCost> {
        None
    }

    fn cost_for_call_site(&self, _file: &Utf8Path, _line: u32) -> Option<RuntimeCost> {
        None
    }

    fn is_loaded(&self) -> bool {
        false
    }
}
