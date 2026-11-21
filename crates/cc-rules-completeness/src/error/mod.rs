//! Granular error probes (5).
//!
//! Detects error-construction sites that ship without typed classes,
//! stable error codes, or actionable recovery paths.

pub mod bare_reraise;
pub mod errcode_collision;
pub mod no_errcode;
pub mod no_typed_class;
pub mod swallowed_with_log;
