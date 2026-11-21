# Clean Code V12 — Finding Schema

schema-version: 1
crate: cc-finding
canonical-format: SARIF 2.1.0 (archive) + reviewdog RDFormat (transport)

## Tier-0 forever rules atop

Every finding emitted by Tier-0 probes (Family 0) carries cost-class `BlockingDebt`
— the strongest severity in the system. The kernel rejects merges whose touched
files emit any new BlockingDebt finding (R-REFACTOR + R-CLEAN-1 enforced here).

---

## Canonical Finding struct

```rust
pub struct Finding {
    pub id: FindingId,                  // UUIDv7 — sortable, machine-friendly
    pub rule_id: &'static str,          // e.g. "cc.shape.fn_length"
    pub category: Category,             // Shape | Slop | Perf | Bug | Taint | ...
    pub subcategory: Option<&'static str>,

    pub location: Location,             // Primary location
    pub related: Vec<RelatedLocation>,  // e.g. dataflow path, dup partner

    pub message: ActionableMessage,     // what + how-to-fix, structured
    pub evidence: Evidence,             // snippet + context for human review

    pub severity: Severity,             // Blocker | Required | Nit
    pub confidence: Confidence,         // 0.0..=1.0, calibrated per probe
    pub cost: CostClaim,                // Asymptotic | RuntimeMs | DollarsPerMonth | BlockingDebt

    pub fix: Option<FixProposal>,
    pub suppress_key: SuppressKey,      // Stable hash for baseline matching
    pub introduced_at: Option<GitRef>,  // Git blame anchor (when known)
    pub probe_version: ProbeVersion,
    pub kernel_version: KernelVersion,
}
```

## Location

```rust
pub struct Location {
    pub file: Utf8PathBuf,              // Project-relative
    pub start: Position,
    pub end: Position,
    pub node_id: Option<NodeId>,        // CPG anchor (preferred over line numbers)
    pub function_qualified_name: Option<String>,
}

pub struct Position {
    pub line: u32,        // 1-indexed
    pub column: u32,      // 1-indexed
    pub offset: u32,      // byte offset
}
```

Line/column track for human display; `node_id` survives reformatting and
is the authoritative anchor for fingerprinting.

## ActionableMessage (R-ERR-ACTION-shaped)

```rust
pub struct ActionableMessage {
    pub headline: String,           // < 80 chars, "what is wrong"
    pub explanation: String,        // < 500 chars, "why it matters"
    pub remediation: Remediation,   // "how to fix"
}

pub enum Remediation {
    AutoFix(FixProposal),                       // machine-applicable
    SuggestedRewrite(String),                   // human-applied diff hint
    DocLink(&'static str),                      // pointer to rule doc
    Multiple(Vec<Remediation>),
}
```

Every Finding must produce a Remediation. No bare "X is bad" without "do Y."
This is the dogfood of R-ERR-ACTION on our own outputs.

## Severity

```rust
pub enum Severity {
    Blocker,    // merge refused (Tier-0 violations, taint hits, CVE-reachable)
    Required,   // must fix before session close (REQUIRED in code-review labels)
    Nit,        // optional (NIT label)
}
```

Severity is not user-tunable. It's a property of the rule.
What's tunable is **suppression** (per finding) and **probe-pack inclusion**
(per repo, per family — except Family 0 which is forced).

## Confidence

```rust
pub struct Confidence(pub f32); // 0.0..=1.0

// Findings below threshold are dropped before emit:
//   - 0.98 for Blocker
//   - 0.85 for Required
//   - 0.60 for Nit
```

Probe authors must calibrate. The confidence-tuning suite (`cc-finding/tests/calibration.rs`)
runs every probe against a labeled corpus and fails CI if a probe's effective
precision diverges > 5% from its declared confidence.

## CostClaim

```rust
pub enum CostClaim {
    /// Code-quality debt that will compound. Used for R-FN-LEN, R-DUP, etc.
    BlockingDebt { weight: u32 },

    /// Asymptotic complexity claim — "this is O(N^2) in N=request_size"
    Asymptotic {
        order: BigO,                    // O1 | OLogN | ON | ONLogN | ON2 | ON3 | OExp
        param: &'static str,            // what N refers to
        scenario: &'static str,         // when it bites
    },

    /// Runtime-ms claim grounded in profile data (L0 layer)
    RuntimeMs {
        observed_p50: f64,
        observed_p95: f64,
        observed_p99: f64,
        traces_consulted: u32,
    },

    /// Recurring monetary cost (deps with paid-tier features unused, etc.)
    DollarsPerMonth { estimate: f64, source: &'static str },

    /// Probability-weighted bug cost (taint hits, race conditions)
    BugRisk {
        cwe: Option<u32>,
        exploitability: f32,            // 0..1
        impact: Impact,                 // Confidentiality/Integrity/Availability axes
    },
}
```

The reporter ranks findings by `cost × confidence`, not alphabetical or rule-id.
This is the difference between "1,847 warnings" and "3 findings worth fixing."

## FixProposal

```rust
pub enum FixProposal {
    /// Concrete diff, machine-applicable
    Diff {
        edits: Vec<TextEdit>,
        safety: FixSafety,              // Safe | Unsafe (Ruff model)
        confidence: f32,
    },

    /// Codemod via comby / ast-grep
    Codemod {
        engine: CodemodEngine,
        pattern: String,
        replacement: String,
        scope: CodemodScope,
    },

    /// LLM-proposed rewrite — never auto-applied, human review required
    LlmRewrite {
        original: String,
        proposed: String,
        rationale: String,
        prompt_hash: PromptHash,        // for caching + replay
    },
}

pub enum FixSafety {
    /// Behavior-preserving with ≥99.9% confidence (purely syntactic, scoped)
    Safe,
    /// May change behavior in edge cases — human must confirm
    Unsafe,
}
```

`FixSafety::Safe` fixes auto-apply with `cc fix`. `Unsafe` fixes are surfaced
but never applied without explicit `cc fix --unsafe`.

## SuppressKey (the core of stable baselines)

```rust
pub struct SuppressKey(pub [u8; 32]);  // SHA-256

impl SuppressKey {
    pub fn from_finding(f: &Finding) -> Self {
        // Stable across:
        //   - line number changes (whitespace, reformat, re-order)
        //   - import sorting
        //   - comment edits
        // NOT stable across (intentional):
        //   - the actual code being changed
        //   - the function being moved to a different file
        //   - signature changes

        let mut h = Sha256::new();
        h.update(f.rule_id);
        h.update(f.location.function_qualified_name.as_deref().unwrap_or(""));
        h.update(snippet_normalized(f.evidence.snippet));  // strip ws, sort imports
        h.update(structural_hash(f.location.node_id));     // CPG-shape, not text
        Self(h.finalize().into())
    }
}
```

Inspired by SARIF `partialFingerprints` + Semgrep baseline-commit + detect-secrets
hash strategy. The structural-hash component (via CPG node-shape) is the novel
piece — survives renames + reformats that defeat text-hash-only approaches.

## Evidence

```rust
pub struct Evidence {
    pub snippet: String,                // Pre-trimmed code window for display
    pub context_before: String,         // ≤ 3 lines
    pub context_after: String,          // ≤ 3 lines
    pub data_path: Option<DataFlowPath>, // For taint findings
    pub cpg_node_dump: Option<String>,  // Debug aid (--verbose only)
}
```

## SARIF mapping

| Finding field | SARIF field |
|---|---|
| `rule_id` | `result.ruleId` + `tool.driver.rules[].id` |
| `category` | `result.properties.category` |
| `location` | `result.locations[0].physicalLocation` |
| `message.headline` | `result.message.text` |
| `message.explanation` | `result.message.markdown` |
| `severity` | `result.level` (Blocker→error, Required→warning, Nit→note) |
| `confidence` | `result.properties.confidence` |
| `cost` | `result.properties.cost` (custom) |
| `fix` | `result.fixes[]` |
| `suppress_key` | `result.partialFingerprints["cc/v1"]` |
| `related` | `result.relatedLocations[]` |

## Round-trip guarantees

- Finding → SARIF → Finding: lossless within one schema version.
- Finding → RDFormat → comment: lossy on `cost`, `confidence`, `evidence.cpg_dump`.
  RDFormat is for transport only; SARIF is the archive of record.
- SARIF schema version bump: bump `schema_version` constant; old SARIFs
  rejected with migration advice.

## Streaming + batching

```rust
pub trait FindingSink {
    fn emit(&self, f: Finding) -> Result<()>;
    fn finish(self) -> Result<Summary>;
}
```

Implementations:
- `SarifSink` — writes a single SARIF file at finish
- `RdJsonSink` — line-delimited JSON for piping to reviewdog
- `TtySink` — colored terminal output
- `BaselineDiffSink` — wraps another sink, drops findings whose suppress_key is in baseline
- `CostRankingSink` — buffers, sorts by cost × confidence, emits top-N

## Probe-pack version protocol

```rust
pub struct ProbeVersion {
    pub pack_id: &'static str,          // "cc-tier0", "cc-perf", etc.
    pub pack_semver: &'static str,      // "1.2.3"
    pub kernel_api_min: u32,            // minimum kernel ABI required
    pub kernel_api_max: Option<u32>,    // optional max (default: current)
}
```

Kernel rejects probes whose `kernel_api_min > current_kernel_api`. Forces
explicit upgrades, prevents "silently wrong" results.
