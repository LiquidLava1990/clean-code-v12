# Clean Code V12 — Tier-0 Forever Rule Algorithms

phase: 1-wave-2
status: implementation-spec
audience: engineer implementing each rule

Each rule below is concrete enough to hand to an engineer (or agent) without
further design. Same template per rule:
- inputs (CPG nodes/edges + optional runtime data)
- algorithm (pseudocode-level, language-portable)
- threshold + tunability
- false-positive avoidance
- fix proposal (or none)
- accept criteria

---

## R-FN-LEN — `cc.shape.fn_length` (>50 LOC)

**inputs**: `Function` nodes, `props["line_start"]`, `props["line_end"]`, source bytes

**algorithm**:
```
for each Function f in store.by_kind(Function):
    body_start, body_end = f.body_range()
    logical_loc = 0
    for line in source_bytes[body_start..body_end].lines():
        stripped = line.trim()
        if stripped.is_empty(): continue
        if is_comment_only(stripped, f.language): continue
        logical_loc += 1
    if logical_loc > threshold:
        emit Finding {
            rule_id: "cc.shape.fn_length",
            severity: Blocker,
            confidence: 1.0,
            cost: BlockingDebt { weight: (logical_loc - threshold) * 2 },
            message: actionable("function {{f.name}} is {{logical_loc}} LOC, threshold {{threshold}}",
                                "extract sub-functions; aim for one responsibility"),
        }
```

**threshold**: 50 (configurable per-repo via `.cc/config.toml`)
**fp-avoid**: skip generated files (heuristic: file matches `*.pb.go`, `*_pb2.py`, `*.gen.ts`)
**fix**: none (extraction requires human judgment)
**accept**: 12+12 golden tests; matches manual count within 0 LOC

---

## R-FILE-LEN — `cc.shape.file_length` (>1500)

**inputs**: `File` nodes, source byte count

**algorithm**:
```
for each File f:
    non_blank_non_comment = count_lines(f.source, skip_blank=true, skip_comment_only=true)
    if non_blank_non_comment > threshold:
        emit Finding { ..., cost: BlockingDebt { weight: (n - threshold) / 100 } }
```

**threshold**: 1500
**fp-avoid**: same generated-file skip; vendored deps (`vendor/`, `node_modules/`, `.venv/`) excluded by default config
**fix**: none

---

## R-NEST — `cc.shape.nesting_depth` (>3)

**inputs**: `Function` nodes, `Branch`, `Loop`, `Try`, `Block` children via AST_PARENT

**algorithm**:
```
fn nesting_depth(f: FunctionId, store: &CpgStore) -> u32 {
    let mut max_d = 0;
    fn walk(node: NodeId, depth: u32, max_d: &mut u32, store: &CpgStore) {
        if matches!(node.kind, Branch | Loop | Try) {
            depth += 1;
            *max_d = (*max_d).max(depth);
        }
        for child in store.children_via(AST_PARENT, node) {
            walk(child, depth, max_d, store);
        }
    }
    walk(f.body_id, 0, &mut max_d, store);
    max_d
}
```

**threshold**: 3
**fp-avoid**: `match`/`switch` arms count as siblings, not nested (each arm is depth+1, not cumulative)
**fix**: emit `SuggestedRewrite` showing guard-clause refactor for the deepest path
**cost**: `BlockingDebt { weight: (depth - threshold) * 3 }`

---

## R-PARAMS — `cc.shape.param_count` (>5)

**inputs**: `Function`, `Parameter` children

**algorithm**:
```
positional_count = f.parameters.iter().filter(|p| !p.is_keyword_only && !p.is_self).count()
if positional_count > 5: emit
```

**threshold**: 5 (positional only)
**fp-avoid**: `self`/`this`/`cls` excluded; kw-only and `**kwargs`/`...rest` excluded
**fix**: none (signature change is breaking)

---

## R-CYC — `cc.shape.cyclomatic` (>10)

**inputs**: `Function` body, CFG_NEXT + CFG_BRANCH_TRUE + CFG_BRANCH_FALSE edges

**algorithm**: McCabe — `branches + 1`
```
fn cyclomatic(f: FunctionId, store: &CpgStore) -> u32 {
    let body_nodes = store.by_func(f);
    let branch_count = body_nodes.iter()
        .filter(|n| matches!(n.kind, Branch | Loop) ||
                    (n.kind == Call && is_short_circuit(n)))
        .count();
    branch_count as u32 + 1
}
```

**threshold**: 10
**fp-avoid**: `match` with N arms = N-1 branches (not N)
**accept**: matches `radon cc -s` within ±1 on 100 cpython samples

---

## R-COG — `cc.shape.cognitive` (>15)

**inputs**: same as R-CYC plus AST_PARENT depth

**algorithm**: Sonar Cognitive Complexity (2018 spec)
```
fn cognitive(f: FunctionId, store: &CpgStore) -> u32 {
    let mut score = 0;
    fn visit(node: NodeId, nesting: u32, score: &mut u32, store: &CpgStore) {
        match node.kind {
            Branch | Loop | Try => {
                *score += 1 + nesting;       // base +1, +1 per nesting level
                for child in node.children() {
                    visit(child, nesting + 1, score, store);
                }
            }
            Call if is_recursion(node) => *score += 1,
            BoolOp(_) if mixes_and_or(node) => *score += 1,
            _ => for child in node.children() { visit(child, nesting, score, store); }
        }
    }
    visit(f.body_id, 0, &mut score, store);
    score
}
```

**threshold**: 15
**fp-avoid**: `else if` / `elif` chains count as one structure, not N
**accept**: matches Sonar reference impl on `examples/cognitive/` within ±2

---

## R-DUP — `cc.shape.duplication` (token-shingle ≥6 hits)

**inputs**: token stream from each Function

**algorithm**: locality-sensitive hashing on k-shingles
```
const K: usize = 12;          // tokens per shingle
const B: usize = 64;          // SimHash bits

fn shingle_hashes(f: FunctionId, store: &CpgStore) -> Vec<u64> {
    let tokens = canonicalize(store.tokens_for(f));   // strip whitespace, normalize literals
    if tokens.len() < 30: return vec![];               // too small to hash meaningfully
    tokens.windows(K).map(|w| simhash_64(w)).collect()
}

// At repo scale:
let mut shingle_to_funcs: HashMap<u64, Vec<FunctionId>> = HashMap::new();
for f in functions {
    for h in shingle_hashes(f, store) {
        shingle_to_funcs.entry(h).or_default().push(f);
    }
}
for (h, fs) in shingle_to_funcs {
    if fs.len() < 2: continue;
    for (a, b) in pairs(fs) {
        let overlap = count_shared_shingles(a, b);
        if overlap >= 6 && total_tokens(a) >= 30 && total_tokens(b) >= 30 {
            emit Finding { related: [Location(a), Location(b)] }
        }
    }
}
```

**threshold**: ≥6 shared shingles AND ≥30 tokens per function
**fp-avoid**: getters/setters too short to trigger (token cap); generated code excluded
**fix**: `SuggestedRewrite` showing extract-common-helper diff
**accept**: detects copy-paste-modify; 0 FP on standard getter/setter corpus

---

## R-DEAD — `cc.shape.dead_code`

**inputs**: CG_CALLS edges + entry-point heuristic

**algorithm**: graph reachability
```
fn dead_symbols(store: &CpgStore) -> Vec<NodeId> {
    let entry_points = collect_entry_points(store);
    // Entry points: public API (export keyword, public visibility),
    //               test functions (matches *_test.go, test_*.py, *.test.ts),
    //               main/init,
    //               framework hooks (@app.route, register_blueprint, etc.)

    let reachable = bfs_via(CG_CALLS, entry_points);
    let all_funcs = store.by_kind(Function);
    let dead: Vec<_> = all_funcs.into_iter().filter(|f| !reachable.contains(f)).collect();

    // Filter out dynamic-dispatch escape hatches:
    dead.into_iter().filter(|f| !is_dynamic_target(f, store)).collect()
}

fn is_dynamic_target(f: FunctionId, store: &CpgStore) -> bool {
    // Method on class with __getattr__ / Proxy / reflection
    // Function passed to setattr / Object.defineProperty
    // Decorated with @register / @route / @app.command
    // Match heuristics per language
}
```

**fp-avoid**: language-specific dynamic-dispatch escape hatches must whitelist
**fix**: `Diff::Safe` for unused-import removal; `Diff::Unsafe` for unused-function removal
**accept**: 0 FP on test corpus that includes Flask routes, pytest fixtures, Go init() funcs

---

## R-TYPE — `cc.shape.type_coverage`

**inputs**: `Function.props["signature"]`, `Parameter.props["type"]`, return type, public-flag

**algorithm**:
```
for each Function f in touched_files(diff):
    if !f.is_public: continue                    // only public surface
    untyped = []
    for p in f.parameters: if p.type.is_none() || p.type == "Any": untyped.push(p)
    if f.return_type.is_none(): untyped.push("return")
    if !untyped.empty():
        emit Finding { ..., severity: Required, confidence: 1.0 }
```

**per-language**:
- Python: `Any`, missing annotation, `# type: ignore` without reason
- TS: `any`, implicit any (`noImplicitAny: false` in tsconfig is itself a finding)
- Go: `interface{}` / `any` in public signatures (data: yes; APIs: no)
- Rust: `dyn Any` without clear use, missing return type on `pub fn`

**fix**: none (annotation requires inference; outside Phase 1 scope)
**accept**: dogfood on this codebase — every `pub fn` has full annotations

---

## R-NAME — `cc.shape.naming`

**inputs**: `Function.name`, `Variable.name`, `Class.name`

**algorithm**: composite score
```
fn name_quality(name: &str, kind: NodeKind, scope: ScopeKind) -> NameScore {
    let mut issues = vec![];
    if name.len() == 1 && !is_loop_counter_context(scope) {
        issues.push(OneCharName);
    }
    if abbreviation_dictionary().bad.contains(name.to_lowercase()) {
        issues.push(BadAbbrev(name));
    }
    let entropy = shannon_entropy(name);
    if entropy < 2.0 && name.len() > 4 {                  // "aaaaa", "tmptmp"
        issues.push(LowEntropy);
    }
    let words = split_camel_or_snake(name);
    if words.iter().any(|w| FAKE_THOUGHTFUL.contains(w)) { // "manager_helper_util"
        issues.push(FakeThoughtful);
    }
    NameScore { issues, score: 1.0 - 0.2 * issues.len() as f32 }
}

// FAKE_THOUGHTFUL = ["manager", "helper", "util", "utils", "handler",
//                    "wrapper", "service" (when chained), "thing", "obj"]
// (only triggers when 2+ of these appear in one name)
```

**fp-avoid**: loop counters (`i`, `j`, `k`); known acceptable abbrevs (`id`, `db`, `fn`, `ctx`, `req`, `res`, `err`)
**fix**: none (rename is project-wide refactor)
**accept**: flags `mgr_helper_util_2`; allows `db_id`, `req_ctx`, `i` in `for i in range(n)`

---

## R-NEST-EARLY — `cc.shape.early_return`

**inputs**: `Branch` + `Block` body structure

**algorithm**:
```
for each Branch b in store.by_kind(Branch):
    if b.has_else && body_of(b.else_arm).contains_only_return_or_raise():
        // Pattern: `if cond: ... else: return / raise`
        // Could be: `if not cond: return; ...` (early return)
        emit Finding { ..., fix: Diff::Unsafe(swap_to_guard_clause(b)) }
```

**fp-avoid**: only suggest when the else-arm is < 3 LOC (otherwise might be intentional)
**fix**: `Diff::Unsafe` showing the guard-clause version
**accept**: detects the canonical 5 anti-patterns per language

---

## R-INHERIT — `cc.shape.inheritance_depth`

**inputs**: `Class.props["superclasses"]`, CG_OVERRIDES edges, mixin detection

**algorithm**:
```
for each Class c:
    chain = walk_super(c, max_depth=10)
    if chain.len() > 2 || count_mixins(c) > 1:
        emit Finding { ..., severity: Required }
```

**per-language**:
- Python: MRO walk; mixin = base with no `__init__` and only methods
- TS/JS: extends chain + mixin detection (`Mixin(Base)` pattern)
- Go: embedded types — depth via embed chain, "mixin" = embedded interface
- Rust: trait-bound depth (different semantics — consider only when `dyn Trait` is involved)

**fix**: none (architectural)
**accept**: a Protocol/dataclass-shaped reference codebase passes cleanly

---

## R-ERR-BARE — `cc.bug.bare_catch`

**inputs**: `Try` nodes + `props["catches"]`

**algorithm**:
```
for each Try t:
    for catch in t.catches:
        if catch.exception_type.is_none() ||
           catch.exception_type == "Exception" ||      // Python
           catch.exception_type == "Error" ||          // TS
           catch.exception_type == "any" {             // Go: `_ = err` pattern
            // Allow if catch body re-raises with context
            if !catch_body_reraises_with_context(catch):
                emit Finding { ..., severity: Blocker }
        }
```

**fp-avoid**: top-level `__main__` blocks where bare except is intentional get exempted via `# noqa: cc.bug.bare_catch — top-level main`
**fix**: `Diff::Unsafe` template `except Exception:` → `except SpecificError:` with TODO marker
**accept**: matches the results of an existing bare-except ratchet on a reference codebase

---

## R-ERR-ACTION — `cc.bug.error_message_quality` (LLM probe)

**inputs**: `Function` containing `Return raise`/`throw`, exception construction args

**algorithm**: cached LLM judgment
```
for each raise/throw site:
    msg = extract_message_string(site)
    cache_key = hash(msg + project_fingerprint.error_style)
    score = llm_cache.get(cache_key) or llm_score_message(msg)

    if score.has_what && score.has_how_to_fix:
        skip
    else:
        emit Finding { confidence: score.confidence }
```

**LLM prompt** (cached, project-fingerprint-aware):
> Score this error message on two axes:
> 1. WHAT happened (state, value, cause): 0-1
> 2. HOW to fix (action, env-var, doc-link): 0-1
> Reply: {"what": 0.8, "how": 0.2, "confidence": 0.95, "rationale": "..."}

**fp-avoid**: confidence < 0.6 → don't report
**fix**: `LlmRewrite` proposal with full rewrite + rationale
**accept**: flags `raise Exception("error")`; allows `raise ConfigError("missing key 'api_key' — set ANTHROPIC_API_KEY env var")`

---

## R-REFACTOR — `cc.meta.touch_ratchet`

**inputs**: git diff + health-score per touched file

**algorithm**:
```
fn touch_ratchet(diff: &GitDiff, store: &CpgStore, baseline: &Baseline) -> Vec<Finding> {
    let touched = diff.changed_files();
    let mut violations = vec![];
    for file in touched {
        let new_score = health_score_for_file(file, store);
        let old_score = baseline.score_for(file).unwrap_or(new_score);
        if new_score < old_score {                       // lower = worse
            violations.push(Finding {
                rule_id: "cc.meta.touch_ratchet",
                severity: Blocker,
                cost: BlockingDebt { weight: (old_score - new_score) as u32 },
                message: actionable(
                    format!("file {} health regressed {:.2} → {:.2}", file, old_score, new_score),
                    "refactor on contact: clean what you touched"
                ),
            });
        }
    }
    violations
}
```

**threshold**: any regression (delta < 0)
**fp-avoid**: brand-new files exempt (handled by R-CLEAN-1 instead)
**fix**: none (human cleanup required)

---

## R-CLEAN-1 — `cc.meta.new_file_gate`

**inputs**: git diff (file added) + per-file Tier-0 finding count

**algorithm**:
```
for each file added in diff:
    findings = run_tier0(file, store)
    if !findings.is_empty():
        emit Finding {
            rule_id: "cc.meta.new_file_gate",
            severity: Blocker,
            related: findings.iter().map(|f| Location(f)).collect(),
            message: actionable(
                format!("new file {} has {} Tier-0 violations", file, findings.len()),
                "new code clean from line 1; fix all listed issues before merge"
            ),
        }
```

**fp-avoid**: vendored / generated code skipped (config-driven path patterns)
**fix**: none (file must be cleaned)

---

## Cross-rule invariants

1. Every algorithm operates on the CPG, never on raw source (except byte counts).
2. Every algorithm is deterministic — no hashmap-iteration order leaks.
3. Every algorithm has worst-case O(n × log n) on file size or O(n) on graph size.
   No quadratics in Tier-0; flag as a bug if found.
4. Every algorithm respects `--include` / `--exclude` glob configuration.
5. Every algorithm runs under Salsa caching — pure function of `(CPG, config)`.
6. Every algorithm emits at most one Finding per (rule, function, suppress_key)
   per scan run. No duplicate emits.
7. Every algorithm has a calibration test against a labeled corpus.

## Implementation order (within Wave 2)

```
Day 1:  R-FN-LEN, R-FILE-LEN, R-PARAMS         (trivial counters; smoke-test pipeline)
Day 2:  R-CYC, R-COG                            (CFG-traversal; needs CFG_* edges)
Day 3:  R-NEST, R-NEST-EARLY                    (AST_PARENT walks)
Day 4:  R-NAME, R-INHERIT                       (string-heuristic + class chain)
Day 5:  R-DUP                                   (locality-sensitive hashing — heaviest)
Day 6:  R-DEAD                                  (graph reachability + dynamic-dispatch escapes)
Day 7:  R-TYPE                                  (per-language type-coverage queries)
Day 8:  R-ERR-BARE                              (Try-node iteration, language-specific catch types)
Day 9:  R-REFACTOR, R-CLEAN-1                   (require baseline + git diff plumbing)
Day 10: R-ERR-ACTION                            (LLM probe — last because it requires API plumbing)
```

Self-host gate: after Day 10, `cc check .` on clean-code-v12 source returns
Tier-0 GREEN. If not, fix the rule or fix the code — not lower the threshold.
