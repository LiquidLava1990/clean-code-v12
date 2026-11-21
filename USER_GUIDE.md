# Clean Code V12 — User Guide

This guide walks through installing the `cc` binary, configuring it
for a repo, the four output formats, the baseline workflow, the LSP
daemon, the GitHub Actions integration, and finding suppression. Every
flag and feature documented here is shipped today; anything still in
flight is marked `Status: planned`.

## 1. Installing

### One-line installer (recommended)

```bash
# Linux / macOS (x64 + arm64)
curl -fsSL https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.sh | sh
```

```powershell
# Windows x64
irm https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.ps1 | iex
```

Both install `cc` and `cc-lsp`, verify the release SHA-256 checksum,
and accept `CC_VERSION`, `CC_INSTALL_DIR`, and `CC_BIN_NAME`
environment overrides. If another `cc` (usually the system C compiler)
is already on `PATH`, the CLI is installed as `ccv12` so the C
toolchain keeps working; every `cc ...` command below then reads
`ccv12 ...`.

### Prebuilt archives

Every [GitHub Release](https://github.com/LiquidLava1990/clean-code-v12/releases)
carries `cc-<target>.tar.gz` (Linux, macOS) or `cc-<target>.zip`
(Windows) for `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `aarch64-apple-darwin`, and
`x86_64-apple-darwin`, plus a `.sha256` per archive and a combined
`SHA256SUMS`. The Linux builds are fully static (musl).

### `cargo install`

```bash
cargo install --locked --git https://github.com/LiquidLava1990/clean-code-v12 cc-cli   # `cc`
cargo install --locked --git https://github.com/LiquidLava1990/clean-code-v12 cc-lsp   # `cc-lsp`
```

`~/.cargo/bin` usually precedes `/usr/bin` on `PATH`, so on Linux/macOS
this `cc` shadows the C compiler; rename it (e.g. to `ccv12`) if you
build C code on the same machine.

### From source

```bash
git clone https://github.com/LiquidLava1990/clean-code-v12
cd clean-code-v12
cargo build --release -p cc-cli -p cc-lsp
```

The kernel pins `rust-toolchain.toml` to Rust 1.85; `rustup` fetches
it automatically.

## 2. Configuration via `.cc/config.toml`

Drop `cc init` in any repo to scaffold a default config:

```bash
cd /path/to/repo
cc init
```

That creates `.cc/config.toml` and an empty `.cc/baseline.json`. The
config is `serde`-driven; an empty file is valid because every field
has a sensible default.

### Example `.cc/config.toml`

```toml
[project]
name = "my-repo"
# Optional: force a language for misnamed fixtures. Empty = autodetect.
languages = []

[ignore]
paths = [
  "vendor/**",
  "**/*.gen.ts",
  ".cc/**",
]

[rules."cc.shape.fn_length"]
# Tier-0 rules cannot be disabled; thresholds CAN be raised.
[rules."cc.shape.fn_length".thresholds]
max_loc = 50

[rules."cc.shape.naming_drift"]
enabled = true
# Severity downgrades are allowed; upgrades are rejected at load.
severity_override = "nit"

[rules."cc.shape.duplication"]
[rules."cc.shape.duplication".paths]
# Per-rule include / exclude — overrides the repo-wide ignore.
exclude = ["tests/**"]

[baseline]
path = ".cc/baseline.json"

[fingerprint]
# Project fingerprint controls how `cc-incremental` invalidates cache.
# Defaults are good for 99% of repos; tweak only if you see false hits.
```

### Validation

`cc check` validates the config on every run. Validation errors
include the offending rule id, the unsupported severity transition, or
the malformed glob — and the actionable next step.

## 2b. Harness-first workflow

V12 enforces test-first refactoring. **Always harness first, fix
second.** Before touching code, scaffold the three-layer pre-refactor
safety net:

```bash
cc harness init <repo>          # scaffold + baseline
# ... fix findings, refactor ...
cc harness verify <repo>        # confirm no drift
cc harness regenerate <repo>    # ratify deliberate API changes
```

`cc harness init` scaffolds the harness package under
`<repo>/tests/cc_harness/` and captures a baseline of six JSON
snapshots. The seven layers are:

| Layer | What it catches | Snapshot file |
|---|---|---|
| **L1 — Imports** | Module rename/split, broken imports, missing deps | none — pytest-parametrised over discovery |
| **L2 — Public signatures** | Param rename/reorder, new keyword arg, default changes, deleted public class | `tests/cc_harness/snapshots/signatures.json` |
| **L3 — Exception shapes** | `except: pass` → re-raise; narrowing `Exception` to `ValueError`; new try blocks | `tests/cc_harness/snapshots/exception_shapes.json` |
| **L4 — Dependencies** | New imports (architectural drift), dead-import leaks after deletion | `tests/cc_harness/snapshots/dependencies.json` |
| **L5 — Slop markers** | New `TODO` / `FIXME` / `HACK` / `XXX` / `WORKAROUND` / `KLUDGE` / `DEPRECATED` | `tests/cc_harness/snapshots/slop_markers.json` |
| **L6 — Public API** | Silent additions/removals from `__all__` (or implicit public surface) | `tests/cc_harness/snapshots/public_api.json` |
| **L7 — Suppressions** | New `# noqa` / `# type: ignore` / `# pylint: disable` / `# pyright: ignore` / `# cc-allow:` | `tests/cc_harness/snapshots/suppressions.json` |

The harness skips known-external dependencies (Playwright, torch,
fastapi, etc.) gracefully — missing optional deps become
`pytest.skip`, not failures. Project-local extensions live in
`tests/cc_harness/config.py`:

```python
EXTRA_EXTERNAL_DEPS = ("my_proprietary_sdk",)
EXTRA_SKIP_BASENAMES = ("custom_entrypoint.py",)
```

`cc harness verify` runs `python -m pytest tests/cc_harness/` and
passes the exit code through (0 on green, 1 on drift). `cc harness
regenerate` re-runs the snapshot capture so a deliberate API change
becomes the new baseline; commit the snapshot diff with a message that
describes the API delta — that diff is the source of truth for code
review.

### Idempotency

`cc harness init` is idempotent. A second run prints:

```
harness already initialized at <repo>/tests/cc_harness — run `cc harness verify <repo>` instead
```

and exits clean. To upgrade an existing harness, delete
`tests/cc_harness/` and re-init.

### Python is required

The harness is Python-only today; Rust / Go / TypeScript layers are
planned. If `cc harness init` reports `python` not found, install
Python 3.10+ and ensure `python` (or `python3`) is on `PATH`, then
retry. Pytest is required for `cc harness verify` (`pip install
pytest` if missing).

## 3. Output formats

`--format` selects the emit shape. Default is `tty`.

| Format | Use case | Schema |
|---|---|---|
| `tty` | Local dev, human-readable | colored, one finding per stanza |
| `sarif` | CI: GitHub code scanning, GitLab security dashboard | [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html) JSON |
| `rdjson` | CI: reviewdog inline PR comments | [reviewdog rdjson](https://github.com/reviewdog/reviewdog/tree/master/proto/rdf) |
| `json` | Custom downstream tooling, jq pipelines | one `Finding` JSON object per line |

Examples:

```bash
cc check . --format tty
cc check . --format sarif --output cc-results.sarif
cc check . --format rdjson > cc-diff.rdjson
cc check . --format json | jq '.rule_id' | sort | uniq -c
```

## 4. Baseline workflow

A baseline is a JSON snapshot of the findings you've **decided not to
fix today**. Future runs silence anything whose `SuppressKey` is in
the baseline, so you only see new findings.

### Producing a baseline

```bash
# Run on the current state, write the result as the baseline.
cc check . --format json --output .cc/baseline.json

# Subsequent runs silence everything in the baseline.
cc check . --baseline .cc/baseline.json
```

### Ratcheting forward

When a finding gets fixed, regenerate:

```bash
cc check . --format json --output .cc/baseline.json
git commit -m "ratchet baseline" .cc/baseline.json
```

The baseline is committed; ratcheting is reviewable in PR diffs.

### Diff against `main` in CI

Today the CLI's `--baseline` accepts a path, not a git ref. The
[`.github/workflows/cc-check.yml`](./.github/workflows/cc-check.yml)
review job synthesises a baseline at runtime by checking out the merge
base, running `cc check --format json` against it, and feeding the
output back into the PR-head invocation. See the workflow for the
canonical recipe.

`Status: planned` — direct `--baseline <git-ref>` support is
on the Phase-6 docket; until then the workflow does the synthesis.

## 5. LSP integration

The `cc-lsp` binary speaks LSP over stdio. Build it with
`cargo build --release -p cc-lsp` and configure your editor to spawn
it on supported file types.

### VS Code

A VS Code extension lives in [`editors/vscode`](./editors/vscode/README.md)
(build the `.vsix` locally; it is not on the Marketplace yet). Alternatively, any generic LSP client (e.g.
[`mattn/vscode-lsp-client`](https://github.com/mattn/vscode-lsp-client)
or [`coc.nvim`](https://github.com/neoclide/coc.nvim) inside VS Code)
can wire `cc-lsp`:

```jsonc
// .vscode/settings.json
{
  "lsp-client.servers": [
    {
      "name": "cc-lsp",
      "command": ["cc-lsp"],
      "languages": ["python", "typescript", "go", "rust"]
    }
  ]
}
```

### Helix

```toml
# ~/.config/helix/languages.toml
[language-server.cc-lsp]
command = "cc-lsp"

[[language]]
name = "rust"
language-servers = ["rust-analyzer", "cc-lsp"]

[[language]]
name = "python"
language-servers = ["pylsp", "cc-lsp"]
```

### Neovim (built-in `vim.lsp`)

```lua
vim.lsp.start({
  name = "cc-lsp",
  cmd = { "cc-lsp" },
  root_dir = vim.fs.dirname(vim.fs.find({ ".cc", ".git" }, { upward = true })[1]),
  filetypes = { "python", "typescript", "go", "rust" },
})
```

### Phase-1 deviations to know about

- Document sync is `FULL` (whole-buffer per change). Incremental sync
  is `Status: planned`. The kernel still caches on
  content-hash, so the cost is small.
- Auto-fix code actions are `Status: planned`.
- Non-`file:` URIs (e.g. `untitled:`, `git:`) are rejected — open the
  buffer from disk to scan it.

## 6. CI integration (GitHub Actions)

Two shipped workflows live under [`.github/workflows`](./.github/workflows):

- **[`cc-check.yml`](./.github/workflows/cc-check.yml)** — full SARIF
  upload to the GitHub Security tab on every push, plus a PR job that
  posts findings as inline review comments via reviewdog.
- **[`dogfood.yml`](./.github/workflows/dogfood.yml)** — Tier-0
  self-check on every PR; fails on any blocker against the kernel's own source.

A reusable composite action lives at
[`.github/actions/cc-check/action.yml`](./.github/actions/cc-check/action.yml).
Drop it into any workflow:

```yaml
- uses: LiquidLava1990/clean-code-v12/.github/actions/cc-check@v0.1.0
  with:
    path: .
    format: sarif
```

## 7. Suppression keys

Every emitted `Finding` carries a `SuppressKey` — a stable SHA-256
fingerprint that survives whitespace, comment, and import-order edits
but flips when the actual code changes. The baseline file stores
these keys.

### How to ignore a finding

Two routes:

1. **Add it to the baseline.** Re-run `cc check . --format json
   --output .cc/baseline.json` and commit the diff. This is the
   recommended path — the suppression is reviewable, dated, and
   ratcheting forward later requires regenerating the baseline.
2. **Disable the rule (or scope it) in `.cc/config.toml`.** Append:

   ```toml
   [rules."cc.shape.naming_drift"]
   enabled = false                           # blanket disable
   # — or —
   [rules."cc.shape.naming_drift".paths]
   exclude = ["src/legacy/**"]               # path-scope skip
   ```

   Tier-0 rules cannot be `enabled = false`; only `severity_override`
   downgrades and path-scope exclusions are allowed.

### Inline `// cc-ignore`-style pragmas

`Status: planned`. The CPG already carries comment ranges so
this is a small probe-runner change, but it isn't shipped yet.
Until then, the baseline is the supported escape hatch.

## See also

- [`README.md`](./README.md) — mission + Tier-0 rules + pack catalog.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — layer diagram, dep graph, extension points.
- [`packs/README.md`](./packs/README.md) — OCI distribution model.
