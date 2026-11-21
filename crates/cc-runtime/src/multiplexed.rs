//! [`MultiplexedRuntime`] — combine multiple [`RuntimeView`]s.
//!
//! Each lookup tries every constituent view in registration order;
//! the first `Some(_)` wins. Allows the kernel to layer pprof CPU
//! data + OTLP latency data + future collapsed-stack views without
//! the caller re-implementing fan-out logic.

use std::sync::Arc;

use camino::Utf8Path;

use crate::cost::RuntimeCost;
use crate::query::RuntimeView;

/// View composed of multiple underlying [`RuntimeView`]s.
///
/// `cost_for_*` returns the first `Some(_)` produced by any
/// constituent, in the order they were [`push`]ed.
///
/// [`push`]: MultiplexedRuntime::push
#[derive(Clone, Default)]
pub struct MultiplexedRuntime {
    views: Vec<Arc<dyn RuntimeView>>,
}

impl std::fmt::Debug for MultiplexedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexedRuntime")
            .field("view_count", &self.views.len())
            .finish()
    }
}

impl MultiplexedRuntime {
    /// Build an empty multiplexer; equivalent to
    /// [`EmptyRuntime`](crate::EmptyRuntime) until views are pushed.
    #[must_use]
    pub const fn empty() -> Self {
        Self { views: Vec::new() }
    }

    /// Append a view. Lookups consult views in push order.
    pub fn push(&mut self, view: Arc<dyn RuntimeView>) {
        self.views.push(view);
    }

    /// Number of constituent views currently registered.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::len not const-stable
    pub fn len(&self) -> usize {
        self.views.len()
    }

    /// `true` when no views have been registered.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::is_empty not const-stable
    pub fn is_empty(&self) -> bool {
        self.views.is_empty()
    }
}

impl RuntimeView for MultiplexedRuntime {
    fn cost_for_function(&self, file: &Utf8Path, qualified_name: &str) -> Option<RuntimeCost> {
        for view in &self.views {
            if let Some(cost) = view.cost_for_function(file, qualified_name) {
                return Some(cost);
            }
        }
        None
    }

    fn cost_for_call_site(&self, file: &Utf8Path, line: u32) -> Option<RuntimeCost> {
        for view in &self.views {
            if let Some(cost) = view.cost_for_call_site(file, line) {
                return Some(cost);
            }
        }
        None
    }

    fn is_loaded(&self) -> bool {
        self.views.iter().any(|v| v.is_loaded())
    }
}
