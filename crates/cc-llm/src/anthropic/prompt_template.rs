//! Canonical prompt-template strings for Anthropic-backed probes.
//!
//! Each template MUST insist on a single-line JSON object as the only
//! output. The shape is documented per template; the parser in
//! [`crate::anthropic::client`] decodes it into [`crate::Judgment`].
//!
//! # Why constants live here, not in probe packs
//!
//! All Anthropic-bound probes share the same response schema (so the
//! parser can be one function). Probe packs supply the
//! `fingerprint_inputs` (file content hash, rule id, surrounding
//! context); the template skeleton is fixed.
//!
//! # Stability contract
//!
//! Editing the body of a template invalidates every cached
//! [`crate::PromptCacheKey`] derived from it. Bump
//! [`PROMPT_TEMPLATE_VERSION`] when you do so, and the on-disk cache
//! (Phase-5+) will partition old vs. new entries.

/// Bumped whenever any template body changes. Mixed into cache keys
/// by callers that want a hard invalidation event.
pub const PROMPT_TEMPLATE_VERSION: &str = "2026-04-27.v1";

/// Slop classifier — "is this snippet low-quality / AI-generated slop?"
///
/// Inputs (in order):
/// 1. file content hash (provenance, NOT used in prompt body)
/// 2. rule id (e.g. `slop.repeated_phrase`)
/// 3. snippet (the actual code/comment to judge)
///
/// Expected response, single-line JSON, one of:
///
/// ```text
/// {"verdict":"clean","confidence":0.0..=1.0}
/// {"verdict":"slop","confidence":0.0..=1.0,"reason":"..."}
/// {"verdict":"unsure"}
/// ```
pub const SLOP_PROBE_TEMPLATE: &str = "\
You are a strict code reviewer. Judge the snippet between <<<SNIPPET>>> markers.\n\
Return ONE LINE of JSON. No prose. No markdown. No code fences.\n\
Allowed shapes:\n\
  {\"verdict\":\"clean\",\"confidence\":0.0..1.0}\n\
  {\"verdict\":\"slop\",\"confidence\":0.0..1.0,\"reason\":\"<=120 chars\"}\n\
  {\"verdict\":\"unsure\"}\n\
Slop = filler comments, AI-tell phrases, redundant restatements, dead helpers,\n\
       commented-out blocks, decorative banners with no info.\n\
Clean = purposeful, terse, type-correct, non-redundant.\n\
Rule id: {rule_id}\n\
<<<SNIPPET>>>\n\
{snippet}\n\
<<<END>>>\n";

/// Comment-vs-code drift classifier — "does the comment still describe
/// the code below it?"
///
/// Inputs (in order):
/// 1. file content hash (provenance)
/// 2. rule id
/// 3. comment text
/// 4. code text
///
/// Same response schema as [`SLOP_PROBE_TEMPLATE`]. `Slop` here means
/// "comment drifted / lies about the code"; `Clean` means "comment
/// still accurate".
pub const COMMENT_DRIFT_TEMPLATE: &str = "\
You judge whether a code comment still matches the code below it.\n\
Return ONE LINE of JSON, no prose, no markdown, no fences.\n\
Allowed shapes:\n\
  {\"verdict\":\"clean\",\"confidence\":0.0..1.0}\n\
  {\"verdict\":\"slop\",\"confidence\":0.0..1.0,\"reason\":\"<=120 chars\"}\n\
  {\"verdict\":\"unsure\"}\n\
Slop = comment is wrong, stale, or misleading about the code.\n\
Clean = comment accurately describes the code.\n\
Rule id: {rule_id}\n\
<<<COMMENT>>>\n\
{comment}\n\
<<<CODE>>>\n\
{code}\n\
<<<END>>>\n";

/// Texture probe — "does this code feel native to the surrounding\n\
/// codebase or grafted on?"
///
/// Inputs (in order):
/// 1. file content hash (provenance)
/// 2. rule id
/// 3. surrounding-context snippet (what idioms the file uses)
/// 4. candidate snippet (what we just added / changed)
///
/// Same response schema as [`SLOP_PROBE_TEMPLATE`]. `Slop` here means
/// "texture mismatch with surrounding code".
pub const TEXTURE_PROBE_TEMPLATE: &str = "\
You judge whether a candidate snippet matches the texture of the surrounding code.\n\
Return ONE LINE of JSON, no prose, no markdown, no fences.\n\
Allowed shapes:\n\
  {\"verdict\":\"clean\",\"confidence\":0.0..1.0}\n\
  {\"verdict\":\"slop\",\"confidence\":0.0..1.0,\"reason\":\"<=120 chars\"}\n\
  {\"verdict\":\"unsure\"}\n\
Slop = candidate uses different idioms, naming, or error style than the surrounding code.\n\
Clean = candidate is indistinguishable in style from the surrounding code.\n\
Rule id: {rule_id}\n\
<<<CONTEXT>>>\n\
{context}\n\
<<<CANDIDATE>>>\n\
{candidate}\n\
<<<END>>>\n";

/// Render a template by substituting `{name}` placeholders.
///
/// Values come from `vars` in order. Unknown placeholders are left
/// intact so a caller can layer multiple passes; missing values raise
/// nothing — the response parser is the source of truth for
/// well-formedness.
///
/// # Example
///
/// ```
/// use cc_llm::anthropic::prompt_template::render;
/// let out = render("hello {name}", &[("name", "world")]);
/// assert_eq!(out, "hello world");
/// ```
#[must_use]
pub fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 64);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}') {
            let key = &after[..close];
            if let Some((_, val)) = vars.iter().find(|(k, _)| *k == key) {
                out.push_str(val);
            } else {
                // Unknown placeholder — keep literal so chained passes work.
                out.push('{');
                out.push_str(key);
                out.push('}');
            }
            rest = &after[close + 1..];
        } else {
            // Dangling `{` — copy the rest verbatim and stop.
            out.push('{');
            out.push_str(after);
            return out;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_substitutes_known_placeholders() {
        let s = render("a {x} b {y}", &[("x", "1"), ("y", "2")]);
        assert_eq!(s, "a 1 b 2");
    }

    #[test]
    fn render_keeps_unknown_placeholders() {
        let s = render("a {x} b {z}", &[("x", "1")]);
        assert_eq!(s, "a 1 b {z}");
    }

    #[test]
    fn render_handles_dangling_brace() {
        let s = render("a {oops", &[]);
        assert_eq!(s, "a {oops");
    }

    #[test]
    fn templates_mention_one_line_json() {
        for tpl in [
            SLOP_PROBE_TEMPLATE,
            COMMENT_DRIFT_TEMPLATE,
            TEXTURE_PROBE_TEMPLATE,
        ] {
            assert!(
                tpl.contains("ONE LINE of JSON"),
                "template missing schema directive: {tpl}"
            );
        }
    }
}
