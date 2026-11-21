//! [`SuppressKey`] — stable SHA-256 fingerprint used for baseline diffs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::finding::Finding;

/// 32-byte SHA-256 hash that survives whitespace, comment and import
/// re-ordering edits but changes when real code changes.
///
/// The shape is inspired by SARIF `partialFingerprints` + Semgrep's
/// `--baseline-commit` scheme + `detect-secrets`. The structural-hash
/// component (CPG node-shape, not text) is the novel piece — it
/// survives renames + reformats that defeat text-only hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SuppressKey(#[serde(with = "byte_array_hex")] pub [u8; 32]);

impl SuppressKey {
    /// Zero-key sentinel — used as a placeholder during builder
    /// construction before the real key is computed.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Compute the suppress key for a fully-populated [`Finding`].
    ///
    /// Stable across:
    /// - line-number changes (whitespace, reformat, re-order)
    /// - import sorting
    /// - comment edits
    ///
    /// Intentionally **not** stable across:
    /// - the actual code being changed
    /// - the function being moved to a different file
    /// - signature changes
    #[must_use]
    pub fn from_finding(f: &Finding) -> Self {
        let mut h = Sha256::new();
        h.update(f.rule_id.as_bytes());
        h.update(b"\x00");
        h.update(
            f.location
                .function_qualified_name
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        h.update(b"\x00");
        h.update(snippet_normalized(&f.evidence.snippet).as_bytes());
        h.update(b"\x00");
        h.update(structural_hash(f).as_bytes());
        Self(h.finalize().into())
    }

    /// Hex representation (lower-case, 64 chars).
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for b in self.0 {
            use std::fmt::Write;
            // hex format never fails on String writes
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

impl Default for SuppressKey {
    fn default() -> Self {
        Self::ZERO
    }
}

impl std::fmt::Display for SuppressKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Normalise a code snippet so whitespace + comment + import edits do
/// not change the suppress key.
///
/// Steps:
/// 1. Strip line/block comments (`//`, `/* */`, `#`).
/// 2. Sort consecutive `import`/`use` lines lexicographically.
/// 3. Collapse all runs of whitespace to a single space.
/// 4. Trim.
pub(crate) fn snippet_normalized(snippet: &str) -> String {
    let no_comments = strip_comments(snippet);
    let import_sorted = sort_imports(&no_comments);
    collapse_whitespace(&import_sorted)
}

fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                consume_until_newline(&mut chars);
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                consume_block_comment(&mut chars);
            }
            '#' => consume_until_newline(&mut chars),
            _ => out.push(c),
        }
    }
    out
}

fn consume_until_newline<I: Iterator<Item = char>>(chars: &mut I) {
    for c in chars.by_ref() {
        if c == '\n' {
            break;
        }
    }
}

fn consume_block_comment<I: Iterator<Item = char>>(chars: &mut I) {
    let mut prev = '\0';
    for c in chars.by_ref() {
        if prev == '*' && c == '/' {
            return;
        }
        prev = c;
    }
}

fn sort_imports(src: &str) -> String {
    let mut out_lines: Vec<String> = Vec::new();
    let mut buffer: Vec<&str> = Vec::new();
    for line in src.lines() {
        if is_import_line(line) {
            buffer.push(line);
        } else {
            flush_imports(&mut buffer, &mut out_lines);
            out_lines.push(line.to_owned());
        }
    }
    flush_imports(&mut buffer, &mut out_lines);
    out_lines.join("\n")
}

fn flush_imports(buf: &mut Vec<&str>, out: &mut Vec<String>) {
    if buf.is_empty() {
        return;
    }
    buf.sort_unstable();
    out.extend(buf.iter().map(|s| (*s).to_owned()));
    buf.clear();
}

fn is_import_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("import ")
        || t.starts_with("from ")
        || t.starts_with("use ")
        || t.starts_with("require ")
}

fn collapse_whitespace(src: &str) -> String {
    // Token-aware normalisation: strip every whitespace character, but
    // when whitespace originally separated two identifier-ish chars,
    // keep one space (so `fn x` and `fnx` stay distinct). Any other
    // whitespace (between punctuation, or adjacent to punctuation) is
    // dropped — that is the part that reformatters churn.
    let mut out = String::with_capacity(src.len());
    let mut just_saw_space = false;
    let mut last_pushed: Option<char> = None;
    for c in src.chars() {
        if c.is_whitespace() {
            just_saw_space = true;
            continue;
        }
        if just_saw_space && needs_word_separator(last_pushed, c) {
            out.push(' ');
        }
        just_saw_space = false;
        out.push(c);
        last_pushed = Some(c);
    }
    out
}

/// True when `prev` (the most recent non-whitespace char) and `next`
/// (the upcoming char) are both identifier-ish, so collapsing the gap
/// between them would merge two distinct tokens.
fn needs_word_separator(prev: Option<char>, next: char) -> bool {
    prev.is_some_and(|p| is_word_char(p) && is_word_char(next))
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Structural hash — currently keyed on CPG `node_id` if available;
/// falls back to `rule_id` + function name when the CPG is not yet wired.
///
/// When the CPG store is online (cc-cpg-store) this will be replaced
/// with a tree-shape hash; the suppress-key contract is forward-
/// compatible because both versions produce stable strings.
fn structural_hash(f: &Finding) -> String {
    f.location.node_id.as_ref().map_or_else(
        || {
            format!(
                "fallback:{}:{}",
                f.rule_id.as_ref(),
                f.location
                    .function_qualified_name
                    .as_deref()
                    .unwrap_or("<anon>")
            )
        },
        |n| format!("node:{}", n.0),
    )
}

mod byte_array_hex {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let mut buf = String::with_capacity(64);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(buf, "{b:02x}");
        }
        s.serialize_str(&buf)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(D::Error::custom(format!(
                "SuppressKey hex string must be 64 chars; got {}; \
                 ensure the producer wrote a SHA-256 digest",
                s.len()
            )));
        }
        let mut out = [0u8; 32];
        for (i, byte_out) in out.iter_mut().enumerate() {
            let hi = hex_nibble(s.as_bytes()[i * 2]).map_err(D::Error::custom)?;
            let lo = hex_nibble(s.as_bytes()[i * 2 + 1]).map_err(D::Error::custom)?;
            *byte_out = (hi << 4) | lo;
        }
        Ok(out)
    }

    fn hex_nibble(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            other => Err(format!(
                "invalid hex byte 0x{other:02x}; \
                 expected 0-9 or a-f"
            )),
        }
    }
}
