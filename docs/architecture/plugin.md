# Authoring a probe pack

> **Status: design document.** This describes the planned dynamic-pack
> workflow. Today every pack is a Rust crate implementing `cc_rules::RulePack`,
> statically linked into `cc` and registered via `Kernel::with_pack`; the
> `cc pack ...` subcommands and `--pack-dir` flag below are not shipped yet.
> See [`packs/README.md`](../../packs/README.md) for what works now.

> A probe pack is a versioned, signed bundle of detection rules distributed via
> OCI. Anyone can publish one. The kernel loads them at startup and runs them
> alongside Family 0 (Tier-0 forever rules) which are compiled in.

## Pack anatomy

```
my-pack/
├── pack.toml              # manifest: id, semver, kernel-api range, deps
├── README.md              # what the pack detects, why
├── LICENSE                # MIT/Apache/BSD only — no AGPL/GPL accepted
├── rules/
│   ├── my_rule.toml       # rule metadata + thresholds + fixture refs
│   └── ...
├── src/
│   ├── lib.rs             # implements `RulePack` trait
│   └── rules/
│       ├── my_rule.rs
│       └── ...
└── fixtures/
    ├── my_rule/
    │   ├── positive.py    # should trigger
    │   └── negative.py    # should not
    └── ...
```

## `pack.toml`

```toml
id          = "my-pack"
version     = "0.1.0"
description = "What this pack detects."
homepage    = "https://github.com/me/my-pack"
license     = "MIT OR Apache-2.0"

[kernel]
api_min = 1                 # Required kernel API version
api_max = 1                 # Optional ceiling

[depends_on]
"cc-builtin" = ">=0.1, <1.0"

[rules]
files = ["rules/*.toml"]
```

## `rules/my_rule.toml`

```toml
id          = "my.family.my_rule"
category    = "Slop"
severity    = "Required"
phase_added = 2

[thresholds]
max_token_count = 500

[paths]
include = ["**/*.py", "**/*.ts"]
exclude = ["**/test_*.py"]

[fixtures]
positive = "fixtures/my_rule/positive.py"
negative = "fixtures/my_rule/negative.py"
```

## The `RulePack` trait

```rust
pub trait RulePack: Send + Sync {
    fn pack_id(&self) -> &'static str;
    fn pack_version(&self) -> &'static str;
    fn rules(&self) -> &'static [&'static dyn Rule];
}

pub trait Rule: Send + Sync {
    fn rule_id(&self) -> &'static str;
    fn category(&self) -> Category;
    fn default_severity(&self) -> Severity;
    fn run(&self, ctx: &RuleContext) -> Vec<Finding>;
}
```

## Building + signing

```bash
# Build
cargo build --release -p my-pack

# Sign with cosign (keyless via OIDC)
cosign sign-blob --yes target/release/libmy_pack.so > my_pack.sig

# Push to OCI registry
oras push ghcr.io/me/my-pack:0.1.0 \
    --artifact-type application/vnd.cc-pack.v1+wasm \
    target/release/libmy_pack.so:application/wasm \
    pack.toml:application/toml \
    my_pack.sig:application/vnd.dev.cosign.signature
```

## Verifying + installing

The kernel verifies pack signatures via Rekor before loading:

```bash
cc pack add ghcr.io/me/my-pack:0.1.0
# → Verifying signature via rekor.sigstore.dev... ok
# → Loading pack with 12 rules.
```

A pack with an invalid signature, mismatched kernel API, or non-permissive
license is **rejected at install time** — no override available.

## Quality bar (enforced by `cc pack publish` checks)

- Every rule has positive + negative fixtures across at least 2 languages.
- Every rule has a doc page in `docs/rules/<family>/<rule_id>.md`.
- Rule code passes `cargo clippy -- -D warnings` against workspace lints.
- No file > 1500 LOC, no function > 50 LOC (Tier-0 dogfood).
- Confidence calibration test passes against labeled corpus.
- Pack-wide `cargo deny check` passes (no AGPL/GPL transitively).

## Pack lifecycle

| Phase | What |
|---|---|
| `draft` | Local development; `cc check --pack-dir ./my-pack` for testing |
| `published` | Pushed to OCI; auto-discoverable via `cc pack search` |
| `verified` | Reviewed by maintainers, eligible for the Recommended Packs list |
| `deprecated` | Marked superseded; install warns but still works |
| `yanked` | Pulled for security/correctness; install refused |

## Reference packs

| Pack | What | Status |
|---|---|---|
| `cc-builtin` | Family 0 (Tier-0 forever rules) — compiled in | shipped |
| `cc-perf` | Family 2 — static performance lints | Phase 2 |
| `cc-deps` | Family 7 — CVE + license + abandonment | Phase 2 |
| `cc-bugs` | Family 3 — correctness | Phase 3 |
| `cc-taint` | Family 4 — SQLi, XSS, command injection | Phase 3 |
| `cc-test` | Family 8 — mutation + flake + coverage | Phase 4 |
