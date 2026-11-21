//! `cc.fmt.todo_no_owner` — flag a `TODO:` comment that lacks owner
//! attribution.
//!
//! Recognised owner forms:
//! - `TODO(name): …`
//! - `TODO(@name): …`
//! - `TODO[name]: …`
//!
//! Anything else — `TODO:`, `TODO -`, bare `TODO` followed by text — is
//! flagged. Distinct from `cc.rot.todo_aging` which fires on every
//! TODO regardless of attribution; this probe only fires when owner
//! is missing.

use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, each_source_file, location_for_file, FormattingFindingBlueprint,
};

/// Family-26 probe R-FMT-TODO-NO-OWNER.
#[derive(Debug, Default, Clone, Copy)]
pub struct TodoNoOwnerRule;

impl Rule for TodoNoOwnerRule {
    fn rule_id(&self) -> &'static str {
        "cc.fmt.todo_no_owner"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Nit
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "TODO comment lacks owner attribution (`TODO(name):`)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for (path, bytes) in each_source_file(ctx) {
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            for (idx, raw) in text.lines().enumerate() {
                if !is_unowned_todo(raw) {
                    continue;
                }
                let lineno = u32::try_from(idx).unwrap_or(u32::MAX).saturating_add(1);
                out.push(emit(path.clone(), lineno));
            }
        }
        out
    }
}

fn is_unowned_todo(line: &str) -> bool {
    let Some(idx) = line.find("TODO") else {
        return false;
    };
    if !is_word_boundary(line, idx) {
        return false;
    }
    let rest = &line[idx + 4..];
    !has_owner_marker(rest)
}

fn is_word_boundary(line: &str, idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    let prev = line.as_bytes().get(idx - 1).copied().unwrap_or(b' ');
    !prev.is_ascii_alphanumeric() && prev != b'_'
}

fn has_owner_marker(rest: &str) -> bool {
    starts_with_bracketed_owner(rest, '(', ')') || starts_with_bracketed_owner(rest, '[', ']')
}

/// True when `rest` begins with `<open><owner><close>` (e.g. `(name)` or
/// `[name]`) and the owner inside is a non-empty identifier consisting
/// only of `[A-Za-z0-9_.-]`. The optional leading `@` (GitHub-handle
/// shorthand) is stripped before the identifier check.
fn starts_with_bracketed_owner(rest: &str, open: char, close: char) -> bool {
    let Some(stripped) = rest.strip_prefix(open) else {
        return false;
    };
    let Some(end) = stripped.find(close) else {
        return false;
    };
    let inner = stripped[..end].trim().trim_start_matches('@');
    !inner.is_empty() && inner.chars().all(is_owner_char)
}

/// Allowed character class for owner identifiers.
const fn is_owner_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

fn emit(path: camino::Utf8PathBuf, lineno: u32) -> Finding {
    let location = location_for_file(path, lineno);
    build_finding(FormattingFindingBlueprint {
        rule_id: "cc.fmt.todo_no_owner",
        severity: Severity::Nit,
        confidence: Confidence::new(0.85),
        location,
        headline: format!("line {lineno}: TODO without owner attribution"),
        explanation: format!(
            "Line {lineno} contains a `TODO` comment with no owner. \
             Unattributed TODOs accumulate as anonymous debt — nobody \
             knows who to ask, who to blame, or whether the item is \
             still relevant."
        ),
        remediation: Remediation::SuggestedRewrite(
            "Annotate the TODO with an owner: `TODO(name):`, \
             `TODO(@github-handle):`, or `TODO[name]:`."
                .into(),
        ),
        snippet: String::new(),
        weight: 0,
    })
}
