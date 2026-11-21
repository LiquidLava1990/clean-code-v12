# Clean Code V12 — Architecture

This document is the technical reference for how `cc` is wired
together. It complements [`README.md`](./README.md) (mission + rule
catalog) and [`USER_GUIDE.md`](./USER_GUIDE.md) (operator-level usage).

## 1. Five-layer model

```text
+--------------------------------------------------------------+
|  L4  Historical          (weekly: churn x complexity x own) |
|      `cc-rules-history`                                     |
+--------------------------------------------------------------+
|  L3  LLM judgment        (per-PR: cached prompts)           |
|      `cc-llm`, slop probes                                  |
+--------------------------------------------------------------+
|  L2  Semantic graph      (per-commit: AST+CFG+PDG+callgraph)|
|      `cc-cpg`, `cc-cpg-store`, taint, concurrency           |
+--------------------------------------------------------------+
|  L1  Syntactic           (per-save: tree-sitter probes)     |
|      `cc-frontend-*`, Tier-0 + slop + perf packs            |
+--------------------------------------------------------------+
|  L0  Runtime signals     (continuous: pprof / OTLP ingest)  |
|      `cc-runtime`                                           |
+--------------------------------------------------------------+
```

Each layer feeds the layer above with progressively richer
context. The kernel composes all five through a single `Finding`
stream that lands in one health score.

## 2. Crate dependency graph

The workspace splits into four bands; downward-only imports are
enforced (Layer N may import Layer N-1, never the other way).

```text
                                +--------------+
                                |    cc-cli    |        --> binary `cc`
                                +-------+------+
                                        |
                                +-------v------+
                                |   cc-kernel  |        --> orchestrator
                                +-+-----+----+-+
                                  |     |    |
        +-------------------------+     |    +--------------------+
        |                               |                         |
+-------v------+                +-------v------+          +-------v------+
| cc-rules-*   |                |  cc-frontend |          |  cc-incremental |
| (25 packs)   |                |  cc-frontend-{python,go,| (salsa cache)|
+--+-----+-----+                |   typescript,rust}      +-------+------+
   |     |                      +-------+------+                  |
   |     |                              |                         |
   |     |                       +------v-------+                 |
   |     |                       |    cc-cpg    |                 |
   |     |                       | cc-cpg-store |<----------------+
   |     |                       +------+-------+
   |     |                              |
   +-----+--+----------+------+--------+
            |          |      |
       +----v----+ +---v---+ +v-----+
       | cc-llm  | |cc-runt| |cc-fingerprint|
       +---------+ +-------+ +------+
                       |
            +----------+-----------+
            |  cc-finding (the     |
            |  finding shape every |
            |  layer emits)        |
            +----------+-----------+
                       |
       +---------------+--------------+
       |               |              |
  +----v----+   +------v------+  +---v-----+
  |cc-sarif |   | cc-rdformat |  |cc-baseline|
  +---------+   +-------------+  +----------+
```

Helpers shared across bands:

- `cc-config` — config load + validate (TOML).
- `cc-diagnostics` — actionable error formatting.
- `cc-score` — deterministic health-score reducer.
- `cc-test-fixtures` — multi-language fixture corpus for the suite.
- `cc-lsp` — LSP daemon (depends on kernel + frontends).

The full member list lives in
[`Cargo.toml`](./Cargo.toml).

## 3. The pack-loading model

Probe packs are the unit of distribution. Every pack implements the
`cc_rules::RulePack` trait:

```rust
pub trait RulePack: Send + Sync {
    fn pack_id(&self) -> &'static str;
    fn pack_semver(&self) -> &'static str;
    fn kernel_api_min(&self) -> u32;
    fn kernel_api_max(&self) -> Option<u32>;
    fn rules(&self) -> &[&'static dyn Rule];
}
```

The kernel exposes a stable ABI version through
`cc_rules::KERNEL_API_VERSION` (currently `1`). When the kernel
registers a pack, the registry rejects:

- packs that require an API version above what the kernel exposes
  (`kernel_api_min > KERNEL_API_VERSION`),
- packs that cap the API version below what the kernel exposes
  (`kernel_api_max = Some(n)` where `n < KERNEL_API_VERSION`),
- duplicate `pack_id` values,
- duplicate `rule_id` values across packs.

Today every built-in pack is **statically linked** into the `cc`
binary. The `with_default_packs` helper registers all 25 packs in
phase order; a custom `cc` build can call `with_pack` to add
out-of-tree packs.

### OCI distribution

Each registered pack also ships an OCI artifact manifest under
[`packs/<pack-id>.oci.json`](./packs/). The manifests are generated
deterministically by `cargo run -p gen-pack-manifests` and describe
the pack as a CodeQL-style OCI artifact. See
[`packs/README.md`](./packs/README.md) for the publish flow and the
third-party-pack contract.

Dynamic loading from a registry (so end-users could `cc check --pack
ghcr.io/foo/lint:1.2.3`) is `Status: planned` — it requires
a stable C ABI for the `RulePack` trait, which is on the Phase-6
roadmap.

## 4. Determinism guarantees (G4)

The kernel commits to four determinism invariants:

1. **Walker order is total**. `walk_repo` sorts every directory entry
   by Unicode codepoint before recursion. The same repo ALWAYS yields
   the same `(path, file_id)` sequence.
2. **Pack registration order is fixed**. `with_default_packs` is the
   single ordered call site; phase 1 → 5 → per-phase declared order.
3. **Per-rule run order is the pack's `rules()` slice**. Rules within
   a pack are NOT re-ordered.
4. **Findings are sorted before emission** by `(path, line, column,
   rule_id, suppress_key)`. Two runs over the same input produce
   byte-identical SARIF / rdjson / json output.

The rayon parallelism is per-file, not per-finding — each file's
rules are emitted in deterministic order, then the per-file finding
vectors are concatenated in the walker's deterministic file order.

## 5. Performance characteristics (G3)

Phase-1 exit gate measured `cc check` against five public reference repos
(listed in [`examples/reference_repos.toml`](./examples/reference_repos.toml)).

| Repo                | Lang   | Files  | Findings | Elapsed | Files/s |
|---------------------|--------|-------:|---------:|--------:|--------:|
| ripgrep             | Rust   |    100 |      398 |  0.67 s |  148.7 |
| typescript-eslint   | TS     |  2 633 |   12 043 |  4.04 s |  651.5 |
| kubernetes/kubectl  | Go     |    430 |    3 151 |  6.90 s |   62.3 |
| cpython/Lib         | Python |  1 738 |   80 257 | 103.6 s |   16.8 |
| poly (handwritten)  | mixed  |      4 |       12 |  0.02 s |  267.4 |

The kubectl + cpython numbers are language-bound — Go's
`interface{}`-heavy returns and Python's pre-PEP-484 stdlib both
explode the type-coverage probe's hit count. Throughput on idiomatic
modern code (TypeScript, Rust) is the headline metric.

p95 < 5 s on 100K-LOC was the G3 gate; ripgrep + typescript-eslint
both clear it. The kubectl + cpython tails are tracked in the perf
backlog (see Phase-6 in the roadmap).

## 6. Extension points

### Writing a custom probe pack

1. **Create a new crate** that depends on `cc-rules`.
2. **Implement `Rule`** for each probe. Pure, allocation-conservative,
   panic-free in the happy path. A rule that does panic emits a
   synthesised `Meta` finding rather than crashing the kernel.
3. **Implement `RulePack`**. Pick a namespaced `pack_id` and unique
   `rule_id`s. Pin `kernel_api_min` to the `KERNEL_API_VERSION`
   constant your crate built against.
4. **Wire it into a custom `cc` build** via `Kernel::with_pack`. Until
   the dynamic loader ships, this is the supported on-ramp.
5. **Generate an OCI manifest** by adapting
   `tools/gen-pack-manifests/src/main.rs` to register your pack
   alongside the built-ins, or hand-write one matching the schema in
   [`packs/README.md`](./packs/README.md).

### Adding a new front-end

1. **Create `cc-frontend-<lang>`** that implements
   `cc_frontend::LanguageFrontend`. Wrap a tree-sitter grammar plus a
   `parse → CpgWriteBatch` lifter.
2. **Register the file extensions** with
   `cc_kernel::language::frontend_for_path`. Keep the dispatch table
   exhaustive — `is_supported_extension` is a hot path.
3. **Add fixtures** under `crates/cc-test-fixtures` and a smoke test
   that asserts the front-end produces a non-empty CPG for at least
   one realistic file.

### Adding a new output sink

`cc_finding::FindingSink` is the trait. Reference implementations
live in `cc-sarif`, `cc-rdformat`, and `cc-cli` (`tty` + `json`). A
custom sink is wired through the CLI via a new `OutputFormat` variant
plus a dispatch arm in `cc-cli/src/runner.rs`.

## See also

- [`README.md`](./README.md) — mission, Tier-0 rules, pack catalog.
- [`USER_GUIDE.md`](./USER_GUIDE.md) — operator-level config + workflows.
- [`packs/README.md`](./packs/README.md) — OCI distribution.
- [`docs/design/TIER_0_ALGORITHMS.md`](./docs/design/TIER_0_ALGORITHMS.md) — Tier-0 rule algorithms.
- [`docs/design/CPG_SCHEMA.md`](./docs/design/CPG_SCHEMA.md) — semantic graph schema.
- [`docs/design/FINDING_SCHEMA.md`](./docs/design/FINDING_SCHEMA.md) — `Finding` type reference.
