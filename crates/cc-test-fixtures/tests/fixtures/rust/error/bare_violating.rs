//! Sample violating cc.error.bare: `.unwrap()` on a fallible call.

use std::fs;

pub fn safe_read(path: &str) -> Vec<u8> {
    // Bare unwrap — panics on failure with no recovery hint.
    fs::read(path).unwrap()
}
