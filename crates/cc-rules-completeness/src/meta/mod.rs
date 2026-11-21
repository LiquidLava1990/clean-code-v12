//! Meta-registry probes (5).
//!
//! Detects functions that participate in pathways/loops without the
//! canonical metadata decorations (meta-registry discipline).

pub mod duplicate_registration;
pub mod envelope_missing;
pub mod fn_missing_decoration;
pub mod io_schema_missing;
pub mod side_effect_undeclared;
