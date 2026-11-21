//! Contract + invariant probes (5).
//!
//! Detects functions and modules whose declared contracts are not
//! mechanically enforced.

pub mod errata_anchor_invalid;
pub mod event_unsigned;
pub mod invariant_unmonitored;
pub mod postcondition_missing;
pub mod precondition_missing;
