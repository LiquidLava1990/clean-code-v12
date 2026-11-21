# Clean Code V12 — rule pack OCI manifests

This directory holds one `<pack-id>.oci.json` per built-in rule pack
registered by `cc-kernel::Kernel::with_default_packs`. The manifests
describe each pack as an OCI artifact suitable for distribution via
`oras` or any OCI-compliant registry (e.g. `ghcr.io`, Docker Hub,
Artifact Registry).

The schema is modeled on [CodeQL's `qlpack`
distribution](https://docs.github.com/en/code-security/codeql-cli/codeql-cli-reference/codeql-pack-publish)
format, simplified for the `cc-rules::RulePack` trait.

## Manifest schema

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.cleancode.v12.rulepack.v1+json",
  "name": "cc-builtin-tier0",
  "version": "0.1.0",
  "kernel-api": { "min": 1, "max": null },
  "rules": [
    "cc.shape.fn_length",
    "cc.shape.file_length"
  ],
  "sources": [
    { "language": "rust", "url": "ghcr.io/liquidlava1990/cc-builtin-tier0:0.1.0" }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `schemaVersion` | int | OCI manifest schema version. Always `2` today. |
| `mediaType` | string | Stable media type identifying a Clean-Code-V12 rule pack. |
| `name` | string | Pack id — must match the `RulePack::pack_id` returned by the runtime pack. |
| `version` | string | Pack semver — must match `RulePack::pack_semver`. |
| `kernel-api.min` | int | Minimum kernel API version the pack requires. |
| `kernel-api.max` | int \| null | Optional kernel API ceiling. `null` = open-ended. |
| `rules` | string[] | Stable rule slugs in the pack's registration order. |
| `sources` | object[] | One `{ language, url }` per language the pack targets. The same URL is repeated when a pack is polyglot. |

## Regenerating the manifests

The manifests are generated deterministically by walking every pack
registered in `cc-kernel::Kernel::with_default_packs`:

```bash
cargo run -p gen-pack-manifests -- --out packs
```

Output is sorted by phase + registration order, so re-running the
binary produces a byte-identical diff. Commit the regenerated files.

## Publishing the built-in packs to ghcr.io

Every tagged release runs the `packs` job in
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which
pushes each manifest with [`oras`](https://oras.land):

```bash
oras push ghcr.io/liquidlava1990/cc-builtin-tier0:0.1.0   --artifact-type application/vnd.cleancode.v12.rulepack.v1+json   cc-builtin-tier0.oci.json:application/json
```

Pull one back with `oras pull ghcr.io/liquidlava1990/cc-builtin-tier0:0.1.0`.
The packs are statically linked into the `cc` binary, so the OCI
artifacts are an inventory you can pin and audit — not something you
need to install.

## Publishing a third-party pack

Anyone can ship their own pack:

1. **Implement `cc_rules::RulePack`** in a Rust crate. Pick a
   namespaced pack id (e.g. `acme.io/lint-pack`) and a unique set of
   rule ids (e.g. `acme.security.<probe>`). The kernel rejects a pack
   that collides on either id with an already-registered pack.
2. **Pin the kernel API window**. `kernel_api_min` should match the
   `KERNEL_API_VERSION` constant your crate built against;
   `kernel_api_max` is normally `None` until the kernel ships a
   breaking ABI bump.
3. **Generate a manifest** with the same shape as the built-ins. You
   can adapt `tools/gen-pack-manifests/src/main.rs` or hand-roll one.
4. **Publish to any OCI registry**:
   ```bash
   oras push ghcr.io/<your-org>/<pack-id>:<version> \
     --artifact-type application/vnd.cleancode.v12.rulepack.v1+json \
     <pack-id>.oci.json
   ```
5. **Tell the kernel to load it**. Dynamic pack loading from OCI
   registries is planned. Until then, packs must be statically
   linked into a custom `cc` build via `Kernel::with_pack`.

## Built-in pack catalog

The following packs ship in the default `cc` build, in registration
order. Probe counts come from `gen-pack-manifests`'s output:

| Pack id | Probes |
|---|---:|
| `cc-builtin-tier0` | 27 |
| `cc-builtin-slop` | 8 |
| `cc-builtin-secrets` | 21 |
| `cc-builtin-perf` | 24 |
| `cc-builtin-completeness` | 30 |
| `cc-builtin-bugs` | 51 |
| `cc-builtin-concurrency` | 8 |
| `cc-builtin-time-math` | 5 |
| `cc-builtin-taint` | 15 |
| `cc-builtin-memory` | 5 |
| `cc-builtin-types` | 23 |
| `cc-builtin-architecture` | 8 |
| `cc-builtin-tests` | 10 |
| `cc-builtin-database` | 6 |
| `cc-builtin-anti-fragility` | 4 |
| `cc-builtin-observability` | 6 |
| `cc-builtin-api` | 6 |
| `cc-builtin-deploy` | 4 |
| `cc-builtin-ops` | 7 |
| `cc-builtin-ci` | 5 |
| `cc-builtin-history` | 5 |
| `cc-builtin-docs` | 8 |
| `cc-builtin-compliance` | 4 |
| `cc-builtin-i18n-a11y` | 5 |
| `cc-builtin-modernize` | 35 |
| `cc-builtin-test-design` | 15 |
| `cc-builtin-supplychain` | 10 |
| `cc-builtin-formatting` | 10 |
| `cc-builtin-iac` | 20 |
| **total** | **385** |

## Planned

- `cosign` signing for pack artifacts.
- Dynamic loader (`cc check --pack ghcr.io/...`) behind a stable pack ABI.
