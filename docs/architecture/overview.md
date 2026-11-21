# Clean Code V12 — Architecture Overview

> Pointer document. Detailed specs live in `docs/design/`. This overview exists so
> a new contributor can route to the right doc in 30 seconds.

## What it is

A polyglot, plugin-driven codebase health kernel. One Rust binary + OCI-distributed
probe packs detect every class of "thing that doesn't work" — slop, bugs, slow
code, dead deps, broken tests, drifted docs, leaking secrets, and the long tail
of failure modes that today's linters miss because each was built to detect one
thing.

## Five-layer architecture

| Layer | Cadence | What it does | Where to read |
|---|---|---|---|
| L0 — Runtime signals | continuous | Ingests pprof / OTLP / collapsed-stack to ground static findings in real cost | `crates/cc-runtime` |
| L1 — Syntactic | every save | AST patterns over tree-sitter | `docs/design/TIER_0_ALGORITHMS.md` |
| L2 — Semantic graph | every commit | Joern-shaped CPG, taint, dataflow, concurrency | `docs/design/CPG_SCHEMA.md` |
| L3 — LLM judgment | every PR | Cached-prompt probes for slop / drift / comment-vs-code | `crates/cc-llm` |
| L4 — Historical | weekly | Git churn × complexity × ownership rot | `crates/cc-rules-history` |

## Tier-0 forever rules (atop everything)

The 16 forever rules are compiled into the kernel binary as Family 0. Never
disable-able. They run on every save in every language. See
`docs/design/TIER_0_ALGORITHMS.md` for concrete pseudocode and the
forever-rules table in `README.md`.

## Crate topology

| Crate | Role |
|---|---|
| `cc-cli` | Binary entry point (`cc` command) |
| `cc-kernel` | Orchestration — runs probes against a CPG |
| `cc-cpg` | Schema (24 node + 12 edge types) |
| `cc-cpg-store` | redb-backed graph store |
| `cc-frontend` + `cc-frontend-{python,typescript,go,rust}` | Per-language tree-sitter lifters |
| `cc-incremental` | Salsa-based incremental query layer |
| `cc-rules` + `cc-rules-tier0` | Rule trait + 16 forever rules |
| `cc-finding` | Canonical Finding struct |
| `cc-sarif` / `cc-rdformat` | Output formats |
| `cc-baseline` | Suppress-key + diff-mode |
| `cc-fingerprint` | Project-fingerprint drift detector |
| `cc-score` | Health score + ratchet |
| `cc-runtime` | L0 runtime-data ingest (Phase 4) |
| `cc-llm` | L3 LLM probe infra (Phase 5) |
| `cc-config` | `.cc/config.toml` parsing |
| `cc-diagnostics` | `cc explain <rule>` rule-catalog rendering |
| `cc-lsp` | Language Server Protocol (Phase 1 Wave 4) |
| `cc-test-fixtures` | Golden corpus (positives + negatives per rule) |

Dependency DAG is documented in `ARCHITECTURE.md`.

## Where to read what

| You want to | Read |
|---|---|
| Understand the mission | `README.md` |
| See the layer + crate design | `ARCHITECTURE.md` |
| Add a Tier-0 rule | `docs/design/TIER_0_ALGORITHMS.md` + `tools/new_rule.sh` |
| Understand the IR | `docs/design/CPG_SCHEMA.md` |
| Emit findings | `docs/design/FINDING_SCHEMA.md` |
| See every shipped pack + probe | `packs/*.oci.json` |
| Run phase exit gates | `tools/verify_phase_exit.sh phase-1` |

## License posture

Permissive (MIT OR Apache-2.0). LGPL deps subprocess-only. AGPL/GPL = forbidden
linkage; mine concepts only. Enforced by `deny.toml` + `cargo-deny check` in CI.
