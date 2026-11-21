# Clean Code V12 — Code Property Graph Schema

schema-version: 1
ir-name: cc-cpg
inspired-by: Joern CPG (Apache-2.0) + MLIR dialects + Roslyn red/green tree
storage: redb embedded KV (one DB per repo)

## Tier-0 forever rules atop

This schema must support, day-1, all 16 forever rules. Any node/edge/property
listed below earns its place by being load-bearing for at least one Tier-0 probe.

## Design principles

1. One node = one syntactic-or-semantic concept. No "Generic" / "Other" buckets.
2. Edges are typed and directional. No untyped graph traversal.
3. Properties are typed via a small `Value` enum, not free-form strings.
4. Everything language-agnostic in core; language-specific in frontends via
   `LanguageExtension` property bag.
5. Schema-version is a constant; bumping it invalidates all caches.
6. Immutable post-build. Updates produce a new generation, garbage-collect old.

---

## Node types (24)

| Kind | Purpose | Required props |
|---|---|---|
| `File` | Source file root | path, language, sha256, line_count |
| `Module` | Module / package / namespace | name, qualified_name |
| `Class` | Class / struct / interface / trait | name, kind (class/struct/iface/trait), superclasses |
| `Function` | Free function / method | name, signature, line_start, line_end, is_async |
| `Method` | Method on class (Function subtype) | + receiver_class |
| `Parameter` | Function parameter | name, type, default, position |
| `Variable` | Local / module / class var | name, type, mutability, scope_kind |
| `Block` | Compound statement | line_start, line_end |
| `Branch` | if / switch / match / ternary | condition_id |
| `Loop` | for / while / do-while / range | body_id, condition_id |
| `Try` | try / catch-block / finally / except | catches: \[ExceptType\] |
| `Call` | Function / method invocation | callee_ref, arg_count, is_dynamic |
| `Read` | Variable / field / global read | target_ref |
| `Write` | Variable / field / global write | target_ref |
| `Literal` | Constant (str / int / float / bool / null) | value, literal_kind |
| `Identifier` | Bare name reference | name, resolves_to (NodeId or Unresolved) |
| `Type` | Type annotation / inferred type | name, kind (primitive/composite/generic/union) |
| `Async` | await / async-with / async-for | inner_id |
| `Event` | Domain event emit (framework-aware) | event_name, contract_ref |
| `External` | Call/import to outside repo boundary | target, kind (stdlib/dep/native) |
| `Comment` | Comment block | text, kind (line/block/docstring) |
| `Decorator` | Python decorator / TS decorator / Rust attribute | name, args |
| `Import` | Import / use / require statement | source, names_imported |
| `Return` | Return / yield / throw | value_id |

## Edge types (12)

| Kind | From → To | Semantics |
|---|---|---|
| `AST_PARENT` | child → parent | Lexical containment |
| `CFG_NEXT` | stmt → stmt | Control flow successor |
| `CFG_BRANCH_TRUE` | Branch → stmt | True-arm successor |
| `CFG_BRANCH_FALSE` | Branch → stmt | False/else-arm successor |
| `PDG_DATA` | def → use | Data dependence |
| `PDG_CONTROL` | predicate → controlled-stmt | Control dependence |
| `CG_CALLS` | Call → Function | Resolved call edge |
| `CG_OVERRIDES` | Method → Method | Method override (subclass → superclass) |
| `DECLARES` | Module → Symbol | Top-level declaration |
| `REFERENCES` | Identifier → declaration | Name resolution edge |
| `EVALUATES_TO` | expr → Type | Inferred type |
| `RAISES` | Function → ExceptionType | Effects: what this function may raise |

## Properties (Value enum)

```rust
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    NodeRef(NodeId),
    NodeList(Vec<NodeId>),
    Position(Position),  // line + column + offset
    Range(Range),
    Hash(Sha256),
    Map(BTreeMap<String, Value>),  // for LanguageExtension only
}
```

## Per-language extensions (`Function.lang_ext`)

| Language | Extra properties on Function nodes |
|---|---|
| Python | `is_method`, `is_classmethod`, `is_staticmethod`, `decorators`, `async_kind` |
| TypeScript | `is_arrow`, `generics`, `overloads`, `is_react_component` |
| Go | `receiver_type`, `is_method_value`, `goroutine_spawned` |
| Rust | `is_unsafe`, `lifetimes`, `where_clauses`, `is_const_fn` |

Stored in `Function.props["lang_ext"] = Value::Map(...)`. Frontends own these.

## Storage layout (redb)

```
nodes:    NodeId → bincode(Node)
edges:    EdgeId → bincode(Edge)
by_kind:  (NodeKind, NodeId) → ()        // index for kind-scoped queries
by_file:  (FileId, NodeId)   → ()        // for file-scoped invalidation
by_func:  (FunctionId, NodeId) → ()      // for function-scoped iteration
edges_out: (NodeId, EdgeKind, NodeId) → EdgeId
edges_in:  (NodeId, EdgeKind, NodeId) → EdgeId
strings:  StringId → String              // intern pool for names + types
meta:     "schema_version" → u32
```

Two-direction edge index trades 2× edge storage for O(1) traversal both ways.

## Construction pipeline

```
source_file
  ↓ tree-sitter parse → Tree
  ↓ frontend lift → Vec<NodeBuilder> + Vec<EdgeBuilder>
  ↓ store.write_batch
  ↓ post-pass: name resolution → REFERENCES edges
  ↓ post-pass: control-flow → CFG_* edges
  ↓ post-pass: type inference → EVALUATES_TO edges
  ↓ post-pass: call resolution → CG_CALLS edges
  ↓ post-pass: dataflow → PDG_DATA + PDG_CONTROL edges
```

Each post-pass is a separate Salsa query → only re-runs on relevant change.

## Frontend contract

```rust
pub trait LanguageFrontend: Send + Sync {
    fn language_name(&self) -> &'static str;
    fn file_extensions(&self) -> &'static [&'static str];

    fn parse(&self, source: &str) -> Result<TreeSitterTree, ParseError>;

    fn lift(&self,
        tree: &TreeSitterTree,
        source: &str,
        store: &mut CpgWriteBatch,
        file_id: FileId,
    ) -> Result<NodeId /* file root */, LiftError>;

    /// Optional: language-specific name resolution.
    /// Default impl does lexical-scope resolution from AST_PARENT chain.
    fn resolve_names(&self, store: &mut CpgWriteBatch) -> Result<(), ResolveError> {
        cc_cpg::default_resolver::resolve(store)
    }
}
```

Lift errors are non-fatal — partial CPG is preferred over no CPG. Missing nodes
get `kind = Unresolved` and `props["error_reason"] = ...`.

## Schema versioning

- `schema_version: u32` constant in `cc-cpg/src/lib.rs`
- bump on any Node/Edge variant addition or property-shape change
- `CpgStore::open()` reads `meta["schema_version"]`; mismatch → reject + advise rebuild
- bincode encoding is generation-stable within a major schema_version

## Out-of-scope for Phase 1 (revisit Phase 3)

- Inter-procedural taint summaries (Phase 3 Wave 1)
- Pointer / aliasing graph (Phase 3 Wave 2)
- Distributed CPG (multi-repo) (Phase 5)
- Binary / bytecode lifting (post-Phase-5)

## Reference impls to study

- Joern `cpg.proto` schema — github.com/ShiftLeftSecurity/codepropertygraph
- Fraunhofer `cpg` library frontend interface — github.com/Fraunhofer-AISEC/cpg
- rust-analyzer `hir` for query patterns
- Astral `ty` Salsa structure for incremental
- ast-grep `napi` types for Rust↔tree-sitter bridge ergonomics
