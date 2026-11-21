//! `cc.error.bare_reraise` — `except Exception: raise` /
//! `try { ... } catch (e) { throw e; }` patterns that lose chain context.
//!
//! Heuristic: scan source text for the canonical idioms. The CPG-level
//! check could walk handlers but Phase-2 frontends don't always emit
//! a re-raise marker; text scan is reliable and cheap.

use cc_cpg::NodeKind;
use cc_finding::{Category, Confidence, Finding, Remediation, Severity};
use cc_frontend::query::nodes_of_kind;
use cc_rules::{Rule, RuleContext};

use crate::helpers::{
    build_finding, enclosing_file_path, location_from_node, looks_like_rule_pack_source,
    CompletenessFindingBlueprint,
};

/// Probe `cc.error.bare_reraise`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BareReraiseRule;

const BARE_RERAISE_PATTERNS: &[&str] = &[
    "except Exception: raise",
    "except: raise",
    "} catch (e) { throw e",
    "} catch(e) { throw e",
    "} catch (err) { throw err",
];

impl Rule for BareReraiseRule {
    fn rule_id(&self) -> &'static str {
        "cc.error.bare_reraise"
    }
    fn category(&self) -> Category {
        Category::Bug
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> Confidence {
        Confidence::new(0.85)
    }
    fn description(&self) -> &'static str {
        "bare re-raise without context (`raise from`)"
    }
    fn run(&self, ctx: &RuleContext<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for file in nodes_of_kind(ctx.batch, NodeKind::File) {
            let Some(path) = enclosing_file_path(ctx.batch, file.id) else {
                continue;
            };
            if looks_like_rule_pack_source(&path) {
                // Rule implementations + their tests embed the pattern
                // strings as detector needles / fixture bodies. Scanning
                // them produces rule-on-rule noise; skip until the AST
                // detector lands (Phase 5 — see helpers TODO).
                continue;
            }
            let bytes = ctx.source.get(&path);
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            for pat in BARE_RERAISE_PATTERNS {
                if !text.contains(pat) {
                    continue;
                }
                let location = location_from_node(ctx.batch, file.id, path.clone());
                out.push(build_finding(CompletenessFindingBlueprint {
                    rule_id: "cc.error.bare_reraise",
                    category: Category::Bug,
                    severity: Severity::Required,
                    confidence: Confidence::new(0.85),
                    location,
                    headline: "bare re-raise drops causal chain".to_owned(),
                    explanation: "`raise` without `from cause` and `throw e` without \
                         a wrapping error lose the original stack trace and chain link. \
                         Production debugging then needs to reconstruct what happened."
                        .into(),
                    remediation: Remediation::SuggestedRewrite(
                        "Use `raise NewError(...) from exc` (Python) or \
                         `throw new WrappedError({ cause: e })` (TypeScript)."
                            .into(),
                    ),
                    snippet: (*pat).to_owned(),
                    weight: 1,
                }));
            }
        }
        out
    }
}
