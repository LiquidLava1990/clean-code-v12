//! Tracers + observability probes (4).
//!
//! Detects functions and call-sites that lack the spans, correlation
//! ids, and structured logging needed to debug a production failure.

pub mod missing_correlation_id;
pub mod public_fn_untraced;
pub mod silent_io;
pub mod span_name_drift;
