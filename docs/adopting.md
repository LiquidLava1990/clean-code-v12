# Adopting Clean Code V12

> Install, scan, baseline, gate — on any Python / TypeScript / Go / Rust repo.

## 1. Install

```bash
# macOS / Linux
curl -fsSL https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.sh | sh
```

```powershell
# Windows
irm https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.ps1 | iex
```

Verify with `ccv12 --version`.

## 2. First run

```bash
cd path/to/your/repo
ccv12 init        # drops .cc/config.toml + an empty baseline
ccv12 check .     # full repo scan, colored output, health score
```

Exit code `0` = clean, `1` = findings. Tier-0 violations surface as Blocker
findings.

## 3. Ratchet with a baseline

Accept today's findings so legacy violations don't block PRs but new ones do:

```bash
ccv12 baseline create --reason "initial adoption"   # writes .cc-baseline.json
git add .cc/ .cc-baseline.json
ccv12 check . --baseline .cc-baseline.json          # reports only new findings
ccv12 baseline status                               # what's left, what's resolved
ccv12 baseline sync                                 # prune resolved entries
```

## 4. Gate it

**pre-commit**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/LiquidLava1990/clean-code-v12
    rev: v0.1.0
    hooks:
      - id: ccv12-lint-blocker
```

**GitHub Actions**

```yaml
# .github/workflows/cc.yml
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
  actions: read
jobs:
  cc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: LiquidLava1990/clean-code-v12/.github/actions/cc-check@v0.1.0
        with:
          baseline: .cc-baseline.json
```

**Any other CI**: install with the one-liner, then run
`ccv12 check . --severity blocker --format sarif --output cc.sarif`.

## 5. Editor

Every release ships `cc-lsp`, a Language Server Protocol daemon. Point any LSP
client at `cc-lsp` (stdio), or build the VS Code extension in
[`editors/vscode`](../editors/vscode/README.md).

## 6. Configure

Defaults are sensible; `.cc/config.toml` scopes paths and tunes rules. Tier-0
forever rules can be tuned but never disabled. See the
[configuration section of the user guide](../USER_GUIDE.md#2-configuration-via-ccconfigtoml)
for the full schema and examples.

## 7. Probe packs

All 29 built-in packs (385 probes) are compiled into the `ccv12` binary — nothing
extra to install. Each pack's manifest is published as an OCI artifact at
`ghcr.io/liquidlava1990/<pack-id>:<version>` for inventory and pinning; see
[`packs/README.md`](../packs/README.md). Dynamic loading of third-party packs
from a registry is planned.

## License

MIT OR Apache-2.0.
