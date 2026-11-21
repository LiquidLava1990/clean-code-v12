//! Per-language fixture byte tables.
//!
//! Each submodule exposes `pub const` byte slices embedded via
//! [`include_bytes!`] from the on-disk corpus under
//! `tests/fixtures/<language>/...`.

pub mod go;
pub mod python;
pub mod rust;
pub mod typescript;
