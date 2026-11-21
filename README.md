# Clean Code V12

[![ci](https://github.com/LiquidLava1990/clean-code-v12/actions/workflows/ci.yml/badge.svg)](https://github.com/LiquidLava1990/clean-code-v12/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/LiquidLava1990/clean-code-v12?include_prereleases)](https://github.com/LiquidLava1990/clean-code-v12/releases)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

**One fast binary that scores the health of any codebase.** `cc` scans Python,
TypeScript/JavaScript, Go, and Rust for god functions, deep nesting, bare
`except`, missing types, leaked secrets, slow code, unsafe concurrency, taint
flows, IaC misconfigurations, and ~380 other problems — then gives the repo one
health score you can ratchet in CI.

- **Single static binary** — no runtime, no daemon, no config required.
- **385 probes in 29 built-in packs**, from Tier-0 "forever rules" to supply-chain and IaC checks.
- **CI-native output** — SARIF (GitHub code scanning), rdjson (reviewdog PR comments), JSON, or colored terminal.
- **Baselines** — adopt on a legacy repo without drowning in findings; only new problems fail the build.
- **Editor support** — `cc-lsp` language server + a VS Code extension.

## 30-second quick start

```sh
# Linux / macOS
curl -fsSL https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.ps1 | iex
```

```sh
cd your-repo
cc check .
```

That's it. `cc check` exits `0` when the repo is clean and `1` when it finds
anything, so the same command works as a CI gate.

> **Linux/macOS note:** most systems already have a C compiler called `cc`. If the
> installer sees one on your `PATH`, it installs the linter as **`ccv12`** instead
> so your C toolchain keeps working — run `ccv12 check .`. Set `CC_BIN_NAME=cc` to
> force the short name.

## Example output

Given this file:

```python
import json

def load(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except:
        return None

def total(orders, tax, discount, shipping, currency, region):
    result = 0
    for order in orders:
        if order:
            for item in order["items"]:
                if item["qty"] > 0:
                    if item["price"] > 0:
                        result += item["qty"] * item["price"]
    return result
```

`cc check .` prints (abridged):

```text
[BLOCKER] cc.shape.nesting_depth: function `total` nests 5 deep (threshold 3)
  --> app/orders.py:13:1
  Deep nesting hides control flow. Function `total` reaches depth 5; the Tier-0 ceiling is 3.
  fix: Use early returns, guard clauses, and helper extraction to keep depth <= 3.
[BLOCKER] cc.shape.param_count: function `total` takes 6 positional params (threshold 5)
  --> app/orders.py:13:1
  fix: Group related parameters into a struct / dataclass; use keyword-only for opt-ins.
[BLOCKER] cc.error.bare: bare exception handler — no specific error type
  --> app/orders.py:6:5
  fix: Catch a specific exception (e.g. `except ValueError as exc:`) and either handle
       the failure or re-raise with `raise ... from exc`.
[REQUIRED] cc.type.coverage: function `load` is missing types (param `path`, return)
  --> app/orders.py:5:1
[REQUIRED] cc.modernize.collapsible_if: nested `if a: if b:` collapsible into `if a and b:`
  --> app/orders.py:18:1

Health: 61/100  (3 Blocker · 3 Required · 4 Nit)
Scanned 1 files in 0.01s (0 skipped)
```

## Install

| Method | Command |
|---|---|
| **Linux / macOS installer** | `curl -fsSL https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.sh \| sh` |
| **Windows installer** | `irm https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.ps1 \| iex` |
| **Prebuilt archive** | Download `cc-<target>.tar.gz` / `.zip` from [Releases](https://github.com/LiquidLava1990/clean-code-v12/releases) (Windows x64, Linux x64/arm64, macOS arm64/x64) |
| **Cargo (from source)** | `cargo install --locked --git https://github.com/LiquidLava1990/clean-code-v12 cc-cli` |
| **pre-commit** | see [pre-commit](#pre-commit) below |
| **GitHub Action** | see [CI](#ci-github-actions) below |

Installer options (environment variables, both scripts):

| Variable | Default | Meaning |
|---|---|---|
| `CC_VERSION` | `latest` | Release tag to install, e.g. `v0.1.0` |
| `CC_INSTALL_DIR` | `~/.local/bin` (Unix), `%LOCALAPPDATA%\Programs\clean-code\bin` (Windows) | Where the binaries go |
| `CC_BIN_NAME` | `cc` (or `ccv12` if another `cc` is on `PATH`) | Installed command name |

Both installers verify the SHA-256 checksum published with each release.
Every archive contains `cc` (the CLI) and `cc-lsp` (the language server).

> `cargo install` puts `cc` in `~/.cargo/bin`, which usually comes before
> `/usr/bin` on `PATH` and therefore shadows the system C compiler. Prefer the
> installer on Linux/macOS, or rename the binary after installing.

Building from a clone (Rust 1.85+, pinned by `rust-toolchain.toml`):

```sh
git clone https://github.com/LiquidLava1990/clean-code-v12
cd clean-code-v12
cargo build --release -p cc-cli -p cc-lsp     # -> target/release/cc, target/release/cc-lsp
```

## Everyday use

```sh
cc check .                          # scan, colored output, exit 1 on findings
cc check . --severity blocker       # only Blocker findings (CI merge gate)
cc check . --format sarif --output cc.sarif   # GitHub code scanning
cc check . --rules cc.shape.fn_length,cc.error.bare
cc init                             # write a default .cc/config.toml
cc baseline create                  # accept today's findings -> .cc-baseline.json
cc check . --baseline .cc-baseline.json   # fail only on new findings
cc fix .                            # apply machine-safe auto-fixes in place
```

Full reference — configuration, output formats, baselines, suppression, LSP —
lives in [`USER_GUIDE.md`](./USER_GUIDE.md).

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/LiquidLava1990/clean-code-v12
    rev: v0.1.0
    hooks:
      - id: cc-lint           # fails on Required + Blocker findings
      # - id: cc-lint-blocker # fails on Blocker findings only
```

The first run compiles the linter inside pre-commit's cache (a few minutes);
later runs are instant.

### CI (GitHub Actions)

```yaml
# .github/workflows/cc.yml
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  cc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: LiquidLava1990/clean-code-v12/.github/actions/cc-check@v0.1.0
        with:
          format: sarif        # findings appear in the Security tab
```

The action downloads the prebuilt release binary — no Rust toolchain needed.

## Forever rules — Tier-0 detection targets

These fire on every language and never get loosened.

| Rule | Threshold | Probe |
|---|---|---|
| **R-FN-LEN** No god functions | > 50 logical lines (excl. blank/comment) | `cc.shape.fn_length` |
| **R-FILE-LEN** No god files | > 1500 lines | `cc.shape.file_length` |
| **R-NEST** No deep nesting | depth > 3 (if/for/while/match/try) | `cc.shape.nesting_depth` |
| **R-PARAMS** No parameter sprawl | > 5 positional params | `cc.shape.param_count` |
| **R-CYC** Cyclomatic complexity | > 10 per function | `cc.shape.cyclomatic` |
| **R-COG** Cognitive complexity | > 15 per function (Sonar formula) | `cc.shape.cognitive` |
| **R-DUP** No duplication | > 6 token-shingle hits across repo | `cc.shape.duplication` |
| **R-DEAD** No dead code | unused imports / orphan vars / unreachable branches | `cc.shape.dead_code` |
| **R-TYPE** Type hints on every signature | public surface in touched files | `cc.type.coverage` |
| **R-NAME** Clear names | entropy + abbreviation + 1-char identifiers | `cc.shape.naming_drift` |
| **R-NEST-EARLY** Early returns | guard clauses preferred over nested else | `cc.shape.nesting_early_return` |
| **R-ERR-BARE** No bare except / catch-all | typed exceptions only | `cc.error.bare` |
| **R-ERR-ACTION** Actionable errors | message includes "what happened AND what to do" | `cc.error.no_action` |
| **R-INHERIT** Composition over inheritance | inheritance depth > 2, mixin > 1 | `cc.shape.no_inheritance` |
| **R-REFACTOR** Refactor on contact | touched-file health score must not regress | `cc.meta.refactor_drift` |
| **R-CLEAN-1** New code clean from line 1 | new files Tier-0-clean or rejected at PR | `cc.meta.new_file_clean` |

## Harness-first refactoring

Before fixing findings in a Python repo, install a safety harness that catches
behavior drift:

```sh
cc harness init <repo>          # scaffold + baseline snapshots
# ...fix findings with any tooling...
cc harness verify <repo>        # confirm nothing drifted
cc harness regenerate <repo>    # ratify deliberate API changes
```

The harness has seven layers: **imports**, **signatures**, **exception shapes**,
**dependencies**, **slop markers** (new `TODO`/`FIXME`/`HACK`…), **public API**
(`__all__`), and **suppressions** (new `# noqa` / `# type: ignore` / `# cc-allow:`).
Snapshots live in `tests/cc_harness/snapshots/`. The harness needs Python 3.10+
and pytest on `PATH`; Rust / Go / TypeScript support is planned.

## Pack catalog

The default build registers 29 packs / 385 probes. `cargo run -p gen-pack-manifests -- --out packs`
regenerates the OCI manifests in [`packs/`](./packs/); each release pushes them to
`ghcr.io/liquidlava1990/<pack>:<version>`.

| Pack | Probes | Focus |
|---|---:|---|
| `cc-builtin-tier0` | 27 | Forever rules (god-fn / god-file / nesting / typing / naming) |
| `cc-builtin-slop` | 8 | LLM slop, drift, comment-vs-code |
| `cc-builtin-secrets` | 21 | Secrets, config leakage, hardcoded keys |
| `cc-builtin-perf` | 24 | Static performance smells |
| `cc-builtin-completeness` | 30 | Structural completeness (errors, registries, events) |
| `cc-builtin-bugs` | 51 | Off-by-one, null-deref, common correctness traps |
| `cc-builtin-concurrency` | 8 | Lock-order, races, async correctness |
| `cc-builtin-time-math` | 5 | Time + arithmetic correctness |
| `cc-builtin-taint` | 15 | Taint flow, injection, SSRF, path traversal |
| `cc-builtin-memory` | 5 | Allocation hotspots, leak smells |
| `cc-builtin-types` | 23 | Type coverage, `Any` in public API |
| `cc-builtin-architecture` | 8 | Layering, dependency direction, cycles |
| `cc-builtin-tests` | 10 | Test smells, brittle asserts |
| `cc-builtin-database` | 6 | N+1, schema drift, transaction misuse |
| `cc-builtin-anti-fragility` | 4 | Retry storms, fallback inversion |
| `cc-builtin-observability` | 6 | Logging, metric, span hygiene |
| `cc-builtin-api` | 6 | API surface stability + versioning |
| `cc-builtin-deploy` | 4 | Deployment + migration safety |
| `cc-builtin-ops` | 7 | Runbooks, kill-switches, dependency hygiene |
| `cc-builtin-ci` | 5 | CI config drift, flaky-step smells |
| `cc-builtin-history` | 5 | Churn × complexity × ownership |
| `cc-builtin-docs` | 8 | Doc drift, missing surface docs |
| `cc-builtin-compliance` | 4 | License contamination, banned deps |
| `cc-builtin-i18n-a11y` | 5 | Internationalisation + accessibility |
| `cc-builtin-modernize` | 35 | Modernization / version skew |
| `cc-builtin-test-design` | 15 | Test design + mutation health |
| `cc-builtin-supplychain` | 10 | Supply-chain attestation + dependency hygiene |
| `cc-builtin-formatting` | 10 | Formatting drift |
| `cc-builtin-iac` | 20 | Terraform / Kubernetes / Docker misconfiguration |

## Architecture

Five layers over a shared code-property graph:

- **L0 — Runtime signals**: pprof / OTLP / collapsed-stack ingest; profile-grounded cost estimates.
- **L1 — Syntactic** (ms): tree-sitter AST patterns, every save.
- **L2 — Semantic graph** (sec): AST + CFG + PDG + call graph for taint, dataflow, concurrency.
- **L3 — LLM judgment** (per PR, optional): cached-prompt probes for slop and drift.
- **L4 — Historical**: git churn × complexity × ownership.

Layer diagram, crate graph, and extension points: [`ARCHITECTURE.md`](./ARCHITECTURE.md).
Writing your own pack: [`packs/README.md`](./packs/README.md) and
[`docs/architecture/plugin.md`](./docs/architecture/plugin.md).

## Contributing

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

The repo dogfoods itself: [`dogfood.yml`](./.github/workflows/dogfood.yml) runs
`cc check` on every PR. Report security issues privately — see [`SECURITY.md`](./SECURITY.md).

## License

Dual-licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE),
at your option.
