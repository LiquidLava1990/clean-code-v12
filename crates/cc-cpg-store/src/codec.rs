//! Bincode encode/decode helpers shared across `read.rs` and `write.rs`.
//!
//! All on-disk bytes go through these two functions so the encoding
//! configuration is identical everywhere. bincode's `standard()` profile is
//! generation-stable within a major schema version (see `CPG_SCHEMA.md`).

use serde::{de::DeserializeOwned, Serialize};

use crate::error::{StoreError, StoreResult};

const fn cfg() -> bincode::config::Configuration {
    bincode::config::standard()
}

/// Encode any serde-serializable value to bincode bytes.
///
/// `what` is a static label used in error messages so the caller doesn't have
/// to thread context through.
///
/// # Errors
///
/// Returns [`StoreError::Encode`] if bincode rejects the value (e.g. an
/// untagged enum the schema didn't anticipate).
pub(crate) fn encode<T: Serialize>(what: &'static str, value: &T) -> StoreResult<Vec<u8>> {
    bincode::serde::encode_to_vec(value, cfg()).map_err(|e| StoreError::encode(what, e))
}

/// Decode bincode bytes into a serde-deserializable value.
///
/// # Errors
///
/// Returns [`StoreError::Decode`] on schema drift or truncated bytes.
pub(crate) fn decode<T: DeserializeOwned>(what: &'static str, bytes: &[u8]) -> StoreResult<T> {
    let (value, _) = bincode::serde::decode_from_slice::<T, _>(bytes, cfg())
        .map_err(|e| StoreError::decode(what, e))?;
    Ok(value)
}
