//! `Sha256` newtype with hex `Display` / `FromStr`.
//!
//! Bincode-friendly: serializes as a fixed 32-byte array. The hex form is
//! only used at human boundaries (logs, JSON, CLI output).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::error::CpgError;

/// A 32-byte SHA-256 digest.
///
/// Serializes as a `[u8; 32]` (bincode-stable). Use [`Sha256::to_hex`] or
/// the [`fmt::Display`] impl for human-readable output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    /// Compute a digest over `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        let out = hasher.finalize();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&out);
        Self(buf)
    }

    /// Return the lowercase hex encoding.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in self.0 {
            // 4-bit nibbles -> single hex char.
            s.push(nibble_to_hex(byte >> 4));
            s.push(nibble_to_hex(byte & 0x0f));
        }
        s
    }

    /// All-zero digest sentinel — useful for "unknown" placeholders.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Sha256 {
    type Err = CpgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(CpgError::InvalidSha256 {
                input: truncate(s),
                reason: "expected 64 characters",
            });
        }
        let mut buf = [0u8; 32];
        let bytes = s.as_bytes();
        for (i, slot) in buf.iter_mut().enumerate() {
            let hi = hex_to_nibble(bytes[i * 2])?;
            let lo = hex_to_nibble(bytes[i * 2 + 1])?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(buf))
    }
}

const fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

fn hex_to_nibble(byte: u8) -> Result<u8, CpgError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CpgError::InvalidSha256 {
            input: format!("non-hex byte 0x{byte:02x}"),
            reason: "non-hex character",
        }),
    }
}

fn truncate(s: &str) -> String {
    if s.len() <= 80 {
        s.to_owned()
    } else {
        format!("{}…", &s[..77])
    }
}
