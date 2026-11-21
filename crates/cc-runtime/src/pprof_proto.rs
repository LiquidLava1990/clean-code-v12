//! Hand-written prost-compatible Rust types for the pprof v3 profile
//! format.
//!
//! # Why hand-written?
//!
//! The canonical schema lives at
//! <https://github.com/google/pprof/blob/main/proto/profile.proto>.
//! Compiling that with `prost-build` requires `protoc` to be on PATH
//! at build time, which is fragile on Windows + bare CI runners.
//!
//! pprof's `Profile` message is small (10 message types, ~20 fields)
//! and the schema has not breaking-changed since 2014, so we mirror
//! the field tags + types directly. `prost::Message` derives the
//! varint / length-delimited encoder; we get parse-only at zero
//! protoc cost.
//!
//! **Fragility note**: if Google ever bumps the schema in a breaking
//! way (extremely unlikely — pprof is a public, frozen format) the
//! field tags below must be updated to match the new
//! `profile.proto`. The doc-test in [`crate::pprof`] and
//! `tests/pprof.rs` would catch the regression.
//!
//! Field tags reproduced verbatim from `profile.proto` v3 (Apache 2.0
//! / public-domain Google upstream).

#![allow(missing_docs)] // Field-level docs would dwarf the proto.

use prost::Message;

/// Top-level pprof `Profile` message.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Profile {
    #[prost(message, repeated, tag = "1")]
    pub sample_type: Vec<ValueType>,

    #[prost(message, repeated, tag = "2")]
    pub sample: Vec<Sample>,

    #[prost(message, repeated, tag = "3")]
    pub mapping: Vec<Mapping>,

    #[prost(message, repeated, tag = "4")]
    pub location: Vec<Location>,

    #[prost(message, repeated, tag = "5")]
    pub function: Vec<Function>,

    #[prost(string, repeated, tag = "6")]
    pub string_table: Vec<String>,
}

/// Kind + unit pairing for one sample-value column.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ValueType {
    #[prost(int64, tag = "1")]
    pub r#type: i64,
    #[prost(int64, tag = "2")]
    pub unit: i64,
}

/// One profile sample = one observed stack with per-type values.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Sample {
    #[prost(uint64, repeated, tag = "1")]
    pub location_id: Vec<u64>,
    #[prost(int64, repeated, tag = "2")]
    pub value: Vec<i64>,
}

/// Loaded binary segment containing a code range.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Mapping {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(uint64, tag = "2")]
    pub memory_start: u64,
    #[prost(uint64, tag = "3")]
    pub memory_limit: u64,
    #[prost(uint64, tag = "4")]
    pub file_offset: u64,
    #[prost(int64, tag = "5")]
    pub filename: i64,
}

/// A program-counter location, inlined frames flattened into `line`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Location {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(uint64, tag = "2")]
    pub mapping_id: u64,
    #[prost(uint64, tag = "3")]
    pub address: u64,
    #[prost(message, repeated, tag = "4")]
    pub line: Vec<Line>,
}

/// One source-line record on a [`Location`].
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Line {
    #[prost(uint64, tag = "1")]
    pub function_id: u64,
    #[prost(int64, tag = "2")]
    pub line: i64,
}

/// Source-level function metadata.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Function {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(int64, tag = "2")]
    pub name: i64,
    #[prost(int64, tag = "3")]
    pub system_name: i64,
    #[prost(int64, tag = "4")]
    pub filename: i64,
    #[prost(int64, tag = "5")]
    pub start_line: i64,
}
