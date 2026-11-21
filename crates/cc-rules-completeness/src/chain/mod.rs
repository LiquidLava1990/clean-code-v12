//! Chain integrity probes (5) — function → registry → typed-error →
//! event chain.

pub mod consumer_no_emitter;
pub mod event_no_consumer;
pub mod fn_in_pathway_no_registry;
pub mod fn_no_event_emit;
pub mod fn_no_typed_error;

use std::collections::BTreeSet;

use cc_cpg::NodeKind;
use cc_frontend::query::{nodes_of_kind, string_prop};
use cc_rules::RuleContext;

/// Collect every `event_name` string-literal argument from `Call` nodes
/// whose callee passes `matcher` (e.g. emit / subscribe predicates).
///
/// Shared by `consumer_no_emitter` and `event_no_consumer` — the only
/// per-rule difference is which side of the chain `matcher` selects.
#[must_use]
pub(crate) fn collect_event_names<'b>(
    ctx: &'b RuleContext<'_>,
    matcher: fn(&str) -> bool,
) -> BTreeSet<&'b str> {
    let mut names = BTreeSet::new();
    for call in nodes_of_kind(ctx.batch, NodeKind::Call) {
        let callee = string_prop(ctx.batch, call.id, "name").unwrap_or("");
        if !matcher(callee) {
            continue;
        }
        if let Some(name) = string_prop(ctx.batch, call.id, "event_name") {
            names.insert(name);
        }
    }
    names
}
