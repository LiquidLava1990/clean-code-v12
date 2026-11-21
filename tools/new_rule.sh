#!/usr/bin/env bash
# Scaffold a new Clean Code V12 probe rule.
#
# Usage: bash tools/new_rule.sh <family> <name>
#   family: shape | slop | perf | bug | taint | concurrent | memory | deps |
#           test | api | db | obs | ops | deploy | math | i18n | a11y |
#           docs | ci | rot | config | arch | compliance | type | fragile |
#           meta
#   name: snake_case identifier (e.g. fn_length)
#
# Result:
#   crates/cc-rules-tier0/src/<family>_<name>.rs   (rule impl stub)
#   crates/cc-test-fixtures/fixtures/<family>/<name>/positive.<ext>
#   crates/cc-test-fixtures/fixtures/<family>/<name>/negative.<ext>
#   docs/rules/<family>/cc.<family>.<name>.md      (user-facing rule doc)

set -euo pipefail

FAMILIES=(
    shape slop perf bug taint concurrent memory deps test api db obs ops
    deploy math i18n a11y docs ci rot config arch compliance type fragile
    meta
)

usage() {
    echo "Usage: $0 <family> <name>"
    echo "  family: ${FAMILIES[*]}"
    echo "  name:   snake_case identifier (e.g. fn_length)"
    exit 2
}

[ $# -eq 2 ] || usage

FAMILY="$1"
NAME="$2"

valid_family=0
for f in "${FAMILIES[@]}"; do
    [ "$f" = "$FAMILY" ] && valid_family=1
done
[ "$valid_family" -eq 1 ] || { echo "unknown family: $FAMILY"; usage; }

if ! [[ "$NAME" =~ ^[a-z][a-z0-9_]*$ ]]; then
    echo "name must match snake_case: ^[a-z][a-z0-9_]*\$"
    exit 2
fi

repo_root() { git rev-parse --show-toplevel 2>/dev/null || pwd; }
cd "$(repo_root)"

RULE_ID="cc.$FAMILY.$NAME"
IMPL_FILE="crates/cc-rules-tier0/src/${FAMILY}_${NAME}.rs"
DOC_FILE="docs/rules/$FAMILY/$RULE_ID.md"
FIXTURE_DIR="crates/cc-test-fixtures/fixtures/$FAMILY/$NAME"

[ -e "$IMPL_FILE" ] && { echo "rule impl already exists: $IMPL_FILE"; exit 1; }

mkdir -p "$(dirname "$IMPL_FILE")" "$(dirname "$DOC_FILE")" "$FIXTURE_DIR"

cat > "$IMPL_FILE" <<EOF
//! Rule \`$RULE_ID\` — TODO: one-line summary.
//!
//! See docs/rules/$FAMILY/$RULE_ID.md for the user-facing description and
//! docs/design/TIER_0_ALGORITHMS.md (if Family 0) for the implementation spec.

use cc_finding::{Finding, Severity};

/// Stable rule identifier.
pub const RULE_ID: &str = "$RULE_ID";

/// Default threshold (override via .cc/config.toml).
pub const DEFAULT_THRESHOLD: u32 = 0; // TODO

/// Run this rule against the given CPG and emit findings.
///
/// # Errors
///
/// TODO: enumerate failure modes.
pub fn run(/* TODO: params */) -> Vec<Finding> {
    // TODO: implement detection algorithm.
    // See docs/design/TIER_0_ALGORITHMS.md for the spec.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_id_matches_constant() {
        assert_eq!(RULE_ID, "$RULE_ID");
    }

    #[test]
    fn positive_fixture_triggers() {
        // TODO: load fixtures/$FAMILY/$NAME/positive.* and assert run() emits.
    }

    #[test]
    fn negative_fixture_silent() {
        // TODO: load fixtures/$FAMILY/$NAME/negative.* and assert run() empty.
    }
}
EOF

cat > "$DOC_FILE" <<EOF
# \`$RULE_ID\`

**Family:** $FAMILY
**Severity:** TODO (Blocker | Required | Nit)
**Phase introduced:** TODO (1 | 2 | 3 | 4 | 5)

## What it detects

TODO: one-paragraph plain-English description.

## Why it matters

TODO: what breaks if this rule is violated.

## How to fix

TODO: actionable remediation. Include a code example.

## Threshold + tuning

\`\`\`toml
[rules."$RULE_ID"]
enabled = true
thresholds = { /* TODO */ }
\`\`\`

## False-positive avoidance

TODO: known patterns that look like violations but aren't.

## References

- Implementation: \`crates/cc-rules-tier0/src/${FAMILY}_${NAME}.rs\`
- Fixtures: \`crates/cc-test-fixtures/fixtures/$FAMILY/$NAME/\`
- Spec (if Family 0): \`docs/design/TIER_0_ALGORITHMS.md\`
EOF

cat > "$FIXTURE_DIR/positive.txt" <<EOF
# TODO: replace with a real positive fixture (file should trigger $RULE_ID).
# Use the language extension matching the target (e.g. positive.py for Python,
# positive.ts for TypeScript). Multiple positives are allowed:
#   positive_python.py, positive_typescript.ts, etc.
EOF

cat > "$FIXTURE_DIR/negative.txt" <<EOF
# TODO: replace with a real negative fixture (file should NOT trigger $RULE_ID).
EOF

echo "scaffolded rule $RULE_ID:"
echo "  impl:    $IMPL_FILE"
echo "  doc:     $DOC_FILE"
echo "  fixtures: $FIXTURE_DIR/"
echo
echo "next steps:"
echo "  1. fill in detection algorithm in $IMPL_FILE"
echo "  2. add positive + negative fixtures (per language) in $FIXTURE_DIR"
echo "  3. write user-facing doc in $DOC_FILE"
echo "  4. add 'mod ${FAMILY}_${NAME};' to crates/cc-rules-tier0/src/lib.rs"
echo "  5. cargo test -p cc-rules-tier0 -- ${FAMILY}_${NAME}"
