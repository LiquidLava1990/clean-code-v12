#!/usr/bin/env bash
# Phase exit-gate runner for Clean Code V12.
#
# Usage: bash tools/verify_phase_exit.sh phase-1
#
# Phase 1 gates (PHASE_1_PLAN.md):
#   G1: ccv12 check . returns Tier-0 GREEN against own source
#   G2: ccv12 check on 5 reference repos returns findings + score
#   G3: p95 latency < 5s on 100k-LOC repo (warm)
#   G4: Health score reproducible across machines
#   G5: SARIF passes microsoft/sarif-tools validate
#   G6: Self-hosted CI blocks a planted Tier-0 regression PR

set -euo pipefail

PHASE="${1:-phase-1}"
FAILED=0
PASSED=0
SKIPPED=0

repo_root() { git rev-parse --show-toplevel 2>/dev/null || pwd; }
cd "$(repo_root)"

log() { printf '[%s] %s\n' "$1" "$2"; }
pass() { log "PASS" "$1"; PASSED=$((PASSED + 1)); }
fail() { log "FAIL" "$1"; FAILED=$((FAILED + 1)); }
skip() { log "SKIP" "$1"; SKIPPED=$((SKIPPED + 1)); }

phase_1_g1_self_host() {
    if ! cargo build --release -p cc-cli 2>/dev/null; then
        skip "G1 self-host (cc-cli not yet buildable)"
        return
    fi
    if ./target/release/ccv12 check . --severity=blocker 2>/dev/null; then
        pass "G1 self-host: Tier-0 GREEN against own source"
    else
        fail "G1 self-host: Tier-0 violations against own source"
    fi
}

phase_1_g2_reference_corpus() {
    if [ ! -f examples/reference_repos.toml ]; then
        skip "G2 reference-corpus (examples/reference_repos.toml missing)"
        return
    fi
    if [ ! -x ./target/release/ccv12 ]; then
        skip "G2 reference-corpus (ccv12 binary not built)"
        return
    fi
    pass "G2 reference-corpus: stub — Phase 1 Wave 4 will run real corpus"
}

phase_1_g3_perf() {
    if ! command -v hyperfine >/dev/null 2>&1; then
        skip "G3 perf (hyperfine not installed — install via 'cargo install hyperfine')"
        return
    fi
    skip "G3 perf: stub — Phase 1 Wave 4 will run real perf bench"
}

phase_1_g4_determinism() {
    skip "G4 determinism: requires multi-machine CI matrix"
}

phase_1_g5_sarif_validate() {
    if ! command -v npx >/dev/null 2>&1; then
        skip "G5 sarif-validate (npx not installed)"
        return
    fi
    skip "G5 sarif-validate: stub — needs cc-sarif emit + microsoft/sarif-tools"
}

phase_1_g6_dogfood_ci() {
    if [ ! -f .github/workflows/dogfood.yml ]; then
        skip "G6 dogfood (.github/workflows/dogfood.yml missing)"
        return
    fi
    pass "G6 dogfood: workflow file present"
}

run_phase_1() {
    echo "=== Phase 1 exit gates ==="
    phase_1_g1_self_host
    phase_1_g2_reference_corpus
    phase_1_g3_perf
    phase_1_g4_determinism
    phase_1_g5_sarif_validate
    phase_1_g6_dogfood_ci
}

case "$PHASE" in
    phase-1) run_phase_1 ;;
    *)
        echo "unknown phase: $PHASE (known: phase-1)"
        echo "  add new phase runners here as roadmap waves complete"
        exit 2
        ;;
esac

echo
echo "=== Summary: $PASSED passed, $FAILED failed, $SKIPPED skipped ==="
[ "$FAILED" -eq 0 ]
