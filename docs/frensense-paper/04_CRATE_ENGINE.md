# Crate: `frensense-engine` — Core Analysis Library

**Path:** `frensense-engine/src/`  
**Role:** The analytical heart. Pure library — no CLI, no binary. Everything else depends on it.

This document covers all modules inside the engine crate. For each module, the purpose, key types, and CS theory are documented.

---

## Public Entry Points (`lib.rs`)

### `analyze_file(source, language, file_path, file_id) -> Result<AnalysisResult>`

Analyzes a single source file. Steps:

1. Load the tree-sitter grammar for the language.
2. Parse the source into a concrete syntax tree (CST).
3. Build `ImportMap` — maps local alias names to package names.
4. Build `HandlerRegistry` — discovers route registrations.
5. Extract `FunctionFingerprint`s for every function in the file.
6. Build `SymbolRegistry` — function/class symbol table.
7. Extract `SemanticOp` normalized IR for taint analysis.
8. (feature-gated) Build `SemanticGraph` and extract temporal events.

### `analyze_project(files) -> Result<ProjectAnalysis>`

Analyzes multiple files, then performs cross-file analysis:

1. Run `analyze_file` on every file in parallel.
2. Merge all per-file `SemanticGraph`s into a global graph.
3. Build the cross-file taint resolver, seed HTTP handlers as taint sources.
4. Propagate taint through the call graph via BFS.
5. Resolve taint at sinks (DbQuery, ShellExecutor) and update fingerprints.
6. Second pass: update `is_registered_handler` using the project-level route registry.
7. Return-value taint propagation: map `let result = dbQuery()` as a tainted binding.

### `AnalysisResult`

```rust
pub struct AnalysisResult {
    pub language: String,
    pub file_path: String,
    pub source: String,
    pub functions: Vec<FunctionFingerprint>,
    pub symbols: SymbolRegistry,
    pub semantic_ops: Vec<SemanticOp>,
    pub import_map: ImportMap,
    pub route_registry: HandlerRegistry,
    pub graph: SemanticGraph,            // feature: full-analysis
    pub temporal_events: Vec<TemporalEvent>, // feature: full-analysis
}
```

---

## Module: `fingerprint/`

### Purpose
Convert a function's AST subtree into a compact multi-resolution vector representation called `FunctionFingerprint`.

### `types.rs` — `FunctionFingerprint`

27-field struct. See [`11_DATA_STRUCTURES.md`](./11_DATA_STRUCTURES.md) for the full annotated table.

Key groups:

| Group | Fields | Captures |
|---|---|---|
| N-gram | `ngram_hashes`, `weighted_ngram_hashes` | Token bag-of-words |
| Signature | `signature_ngrams`, `param_type_ngrams` | Function interface shape |
| Structural | `structural_markers`, `skeleton`, `skeleton_hashes` | Control flow shape |
| Semantic | `semantic_markers`, `motif_hashes` | Dangerous API class membership |
| API | `api_calls`, `api_call_segments`, `tainted_api_calls` | Exact call targets |
| Flow | `data_flow_path_hashes`, `control_flow_hashes` | Source→sink paths |
| Meta | `has_http_decorator`, `is_registered_handler` | Handler classification |

### `hashing.rs` — Token Normalization

- `normalize_token(tok)`: lowercases, strips sigils, collapses string literals to `"__str__"`, numbers to `"__num__"`. This makes `req.body.userId` and `request.body.user_id` hash to the same token.
- `token_ngrams_sorted(tokens, w)`: emit sorted n-gram hashes — permutation-invariant (for Jaccard).
- `token_ngrams_positional(tokens, w)`: emit positionally-keyed n-gram hashes — order-sensitive (for sequence similarity).

### `ast_walkers.rs` — Feature Extractors

One function per feature group. Called by `extraction.rs`:

| Function | Extracts |
|---|---|
| `collect_raw_call_names` | Literal callee expression strings |
| `collect_structural_markers` | AST kind counts (branches, loops, awaits) |
| `collect_type_usages` | Type annotation token strings |
| `count_comment_bytes` | Comment density ratio |
| `extract_argument_call_types` | `(fn_name, arg_pos, arg_kind)` triples |
| `extract_cf_sequence` | Ordered control flow event hashes |
| `extract_control_flow` | CFG path hashes |
| `extract_literal_patterns` | Patterns in string/template literal call arguments |
| `extract_motif_hashes` | Semantic motif group membership hashes |
| `extract_property_accesses` | Object property access names |
| `extract_semantic_markers` | Dangerous API marker hashes |
| `extract_tainted_calls` | API calls where at least one arg is a param name |

---

## Module: `minhash.rs`

### Purpose
Approximate nearest-neighbor search over fingerprint sets using MinHash + banded LSH.

### Algorithm

**Step 1: MinHash Signature**

For a set `S` of n-gram hashes, compute a length-`k` signature:

```
sig[i] = min over h in S of { π_i(h) }
```

where `π_i` is the i-th hash function from the multiply-shift universal family:

```rust
fn minhash_row_hash(value: u64, seed: u64) -> u64 {
    let a = (seed.wrapping_mul(0x517cc1b727220a95).wrapping_add(1)) | 1; // odd
    let b = seed.wrapping_mul(0x9e3779b97f4a7c15);
    value.wrapping_mul(a).wrapping_add(b)
}
```

The forcing of `a` to be odd ensures the construction is 2-universal per Dietzfelbinger 1997.

**Step 2: Banded LSH**

Split the 120-element signature into 40 bands of 12 rows each. For each band, hash the 12 values into a bucket. Two fingerprints sharing a bucket in at least one band are "candidates."

Collision probability for two sets with Jaccard similarity `J`:
```
P(candidate) = 1 - (1 - J^12)^40
```

At `J = 0.71`: `P ≈ 0.5` (50% recall at the similarity threshold).  
At `J = 0.90`: `P ≈ 0.99` (nearly certain recall for high-similarity pairs).

### `LSHIndex` Struct

```rust
pub struct LSHIndex {
    bands:      usize,
    rows:       usize,
    num_hashes: usize,
    buckets:    Vec<FxHashMap<u64, Vec<usize>>>, // band → bucket → [pattern_ids]
}
```

- `insert(id, hashes)`: compute signature, hash each band, insert into bucket.
- `candidates(hashes)`: compute signature, query each band, return union of all matching pattern IDs.

---

## Module: `cfg/`

### `mod.rs` — Control Flow Graph

```rust
pub enum CFEdgeKind { Unconditional, Branch, Merge, BackEdge, Exception }

pub struct BasicBlock<'a> {
    pub id: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub nodes: Vec<Node<'a>>,
    pub dominators: FxHashSet<usize>,
    pub successors: Vec<(usize, CFEdgeKind)>,
    pub predecessors: Vec<usize>,
}

pub struct ControlFlowGraph<'a> {
    pub blocks: Vec<BasicBlock<'a>>,
    entry: usize,
    exit: usize,
    label_index: FxHashMap<String, usize>,
}
```

Key methods:
- `is_reachable(from, to)` — BFS reachability check.
- `dominates(a, b)` — does block `a` dominate block `b`?
- `find_post_dominator(node)` — finds the post-dominator (common successor on all paths).

**CS Theory:** Basic block construction, dominator tree computation via iterative dataflow (Cooper et al. 2001 "A Simple, Fast Dominance Algorithm"), CFG reachability.

### `def_use.rs` — Reaching Definitions

Implements the classical *reaching definitions* dataflow problem:

```
IN[B]  = ∪ OUT[P] for all P ∈ pred(B)
OUT[B] = gen[B] ∪ (IN[B] - kill[B])
```

`DefState` is a lattice element (set of variable → definition mappings). The analysis runs to fixpoint using a worklist algorithm.

Used by taint analysis to determine which variable definitions reach a given use site without building a full SSA form.

---

## Module: `data_flow/`

### `mod.rs` — `TaintOrigin` and `TaintRegistry`

`TaintOrigin` enumerates where untrusted data can originate:

```rust
pub enum TaintOrigin {
    UserInput,    // HTTP request data
    Environment,  // Environment variables
    Database,     // DB query results (secondary taint)
    Network,      // Socket/WebSocket data
    FileSystem,   // File reads
    Custom(String),
}
```

`TaintRegistry` is a **scope-stack lattice**:

```rust
pub struct TaintRegistry {
    scopes:       Vec<FxHashMap<String, TaintOrigin>>,   // var → origin
    symbol_ranges: Vec<FxHashMap<String, (usize, usize)>>, // var → byte range
    field_taint:  Vec<FxHashMap<(String, String), TaintOrigin>>, // (var, field) → origin
}
```

- Each `push_scope()` opens a new block scope.
- `pop_scope()` is **conservative**: conditional sanitization does not untaint. Only an unconditional sanitizer call on the direct path removes taint.
- `taint_field(var, field, origin)` allows field-level granularity: `req.body.x` taints the `x` field of `req.body` without tainting all of `req.body`.

**CS Theory:** May-taint analysis (sound, not complete), monotone dataflow framework, scope-stack lattice where join of tainted and untainted is tainted.

### `normalization.rs` — `SemanticOp`

A normalized intermediate representation for taint propagation, generated from the AST without a full IR compilation step:

```rust
pub enum SemanticOp {
    Binding   { name: String, value_range: ByteRange },   // let x = expr
    Assignment { target: String, value_range: ByteRange }, // x = expr
    Call      { function_name: String, args: Vec<String>, range: ByteRange },
    Return    { value_range: Option<ByteRange> },
    Condition { test_range: ByteRange },
}
```

`ByteRange` carries `start_byte` and `end_byte`. The return-value taint propagation in `analyze_project` uses these ranges to find "the binding whose value range encompasses the call range" — the variable that receives the return value of a tainted function.

### `alias.rs` — `AliasTracker`

Tracks pointer/reference aliases: when `let a = b` and `b` is tainted, `a` becomes tainted. The alias graph is a simple `HashMap<String, Vec<String>>` — good enough for the single-assignment-per-scope pattern common in JS/TS.

### `engine.rs` — `DataFlowEngine`

The per-function taint walker. Walks the function's AST subtree, consulting `TaintRegistry` and `SanitizerRegistry` at each node:

- At assignment/binding nodes: propagate taint from RHS to LHS.
- At call nodes: if any argument is tainted and the callee is a sink, emit a taint finding.
- At call nodes: if the callee is a known sanitizer, untaint the first argument's binding.

Returns a `FunctionTaintSummary` — whether the function propagates taint from any of its parameters to its return value (used by interprocedural analysis).

### `cross_file.rs` — Interprocedural Taint Resolver

Builds a cross-file taint summary using the global call graph:

1. `register_exposed_taint(key, file, origin)` — mark HTTP handler functions as taint sources.
2. `propagate_taint(depth_limit)` — BFS over the call graph, propagating taint from sources through callees.
3. `resolve_taint(fn_name, file, max_depth)` — query whether a given function is reachable from a taint source.

**CS Theory:** Interprocedural taint analysis, function summary approach, call graph BFS propagation.

### `taint_metrics.rs` — `TaintMetrics`

Computes two metrics from a function's taint walk:

- `taint_branch_ratio`: fraction of tainted-variable accesses that appear inside a conditional branch. High ratio (> 0.85) with a validator name suggests the function is a genuine validator, not a vulnerable function that happens to check input.
- `has_validation_name`: does the function name match patterns like `validate_*`, `check_*`, `sanitize_*`, `verify_*`?

These feed into the `composition` layer's L3 suppression logic.

### `sanitizer.rs` — `SanitizerRegistry`

Hardcoded list of known sanitizer functions per language:

```
// TypeScript/JavaScript
DOMPurify.sanitize, sanitizeHtml, escapeHtml, xss, validator.escape,
parameterize, escape, encodeURIComponent, encodeURI, htmlspecialchars,
mysql.escape, mysql2.escape, pg.escapeLiteral, knex.raw.bind, ...

// Rust
html_escape::encode_text, ammonia::clean, sqlx::query!, diesel::sql_query, ...
```

---

## Module: `corpus/`

### `pattern.rs` — `CorpusPattern`

```rust
pub struct CorpusPattern {
    pub id: String,
    pub positives: Vec<FunctionFingerprint>,  // vulnerable examples
    pub negatives: Vec<FunctionFingerprint>,  // fixed/safe examples
    pub semantic_filter: SemanticFilter,
    pub observation: Option<String>,
    pub impact: Option<String>,
    pub improvement: Option<String>,
    pub expected_context: Option<FileContext>,
    pub cwe: Option<String>,
    pub cvss: Option<f32>,
    pub owasp: Option<String>,
    pub severity: Option<String>,
    pub runtime_probe: Option<String>,
}
```

### `semantic.rs` — `SemanticFilter`

Pre-match gate. If the candidate function fails any constraint, scoring is skipped entirely. This is the primary O(1) false-positive guard.

```rust
pub struct SemanticFilter {
    pub contains_call_to:               Vec<String>,  // must have these calls
    pub must_not_contain_call_to:       Vec<String>,  // must NOT have these
    pub contains_node_type:             Vec<String>,  // must have these AST kinds
    pub must_not_contain_node_type:     Vec<String>,  // must NOT have these
    pub required_taint_flows:           Vec<(String, String)>, // source→sink flows
    pub contains_import:                Vec<String>,  // must import these packages
    pub must_not_contain_import:        Vec<String>,  // must NOT import these
    pub function_name_regex:            Option<String>,
    pub must_not_match_function_name:   Vec<String>,
    pub must_not_match_file_path_pattern: Vec<String>,
}
```

### `motifs.rs` — Semantic Motif Table

Motifs are **semantic equivalence classes** of API calls. Registered at compile time as `&'static` slices. At fingerprint extraction time, every call that matches a motif member is hashed under `hash(motif_name)` instead of (or in addition to) `hash(literal_name)`.

Selected motifs:

| Motif Name | Example Members |
|---|---|
| `UserInputSource` | `req.body`, `req.query`, `c.Query`, `r.FormValue`, `@RequestParam` |
| `CommandExecutionSink` | `exec`, `execSync`, `spawn`, `Command::new`, `os.system`, `subprocess.run` |
| `SqlSink` | `db.query`, `pool.query`, `execute`, `raw`, `knex.raw` |
| `OpenRedirectSink` | `res.redirect`, `ctx.redirect`, `http.Redirect` |
| `PathSink` | `fs.readFile`, `path.join`, `open`, `std::fs::read` |
| `NetworkFetchSink` | `fetch`, `axios.get`, `got`, `request`, `http.get` |

This makes a pattern trained on Express's `exec()` automatically detect the same pattern in Node's `spawn()` and Rust's `Command::new()` — cross-framework generalization without extra corpus examples.

### `flow_fingerprint.rs` — Intra-Function Flow Path Hashing

Extracts abstract source-to-sink data flow paths from a function body without building a full program dependence graph.

Algorithm (O(n²) in function body size):
1. Find all assignments where RHS touches a `UserInputSource` motif → `tainted_vars: HashMap<var_name, source_motif>`.
2. For each tainted variable, find call sites in the body where it appears as an argument and the callee matches a sink motif.
3. Record the abstract path `[source_motif, ..., sink_motif]` as a `FlowPath`.
4. Hash each `FlowPath` with FxHasher — the result is variable-renaming invariant.

**CS Theory:** Lightweight program slicing, alpha-equivalence invariance, abstract taint paths.

### `registry.rs` — `PatternRegistry`

The matching index. See [`11_DATA_STRUCTURES.md`](./11_DATA_STRUCTURES.md) for the full struct. Core methods:

- `scan_function(fp, context)` — run the full matching pipeline for one function.
- `lsh_candidates(fp)` — retrieve candidate patterns from the LSH index.
- `score_against(fp, pattern, config)` — compute 15-D similarity + contrastive score.
- `verify_taint(fp, context)` — run the DataFlowEngine and return `FunctionTaintSummary`.

### `source_sink.rs` — `CorpusSourceSinkRegistry`

Stores the source and sink function lists extracted from the corpus patterns themselves. At bundle build time, the bundler scans every positive corpus file and extracts calls to known sink functions, building a per-pattern list. At scan time, this list supplements the hardcoded `SanitizerRegistry` and `motifs.rs` definitions.

---

## Module: `pattern/`

### `scorer.rs` — `PatternScorer` and `ScorerConfig`

`ScorerConfig` holds every tunable scoring parameter as named fields with documented defaults. Nothing is hardcoded in logic — all constants live in `ScorerConfig::default()`.

Key scoring stages:
1. Compute `RawDimensions` (15 Jaccard/cosine similarities).
2. Apply identity gate: `gate = min(max(api_sim, semantic_sim, ast_sim, motif_sim, flow_sim) * 2.5 + 0.1, 1.0)`.
3. Compute weighted sum: `vuln_score = Σ dim_i * weight_i`.
4. Apply gate: `base_score = vuln_score * gate`.
5. Contrastive penalty: `score = base_score - neg_penalty_weight * neg_score` (where `neg_score` is the score against the pattern's negative examples).
6. Apply structural score (kind diversity, profile boost).
7. Apply per-context penalty (cross-lingual penalty if languages differ).
8. Apply sigmoid calibration: `confidence = σ(A * score + B)`.

### `similarity.rs` — `RawDimensions`

Computes each of the 15 similarity values using sorted-set Jaccard:

```
Jaccard(A, B) = |A ∩ B| / |A ∪ B|
```

For sorted vectors: `intersect_sorted(a, b)` (merge-join O(n+m)), `union_size = len(a) + len(b) - intersection`.

`weighted_score(weights)` applies the gate formula above and returns the final scalar.

### `evidence.rs` — `MatchEvidence`

The per-dimension breakdown attached to every corpus finding. Makes findings interpretable — the equivalent of a compiler telling you which variable has a type error.

```rust
pub struct MatchEvidence {
    pub ngram_sim:         f64,
    pub ast_sim:           f64,
    pub semantic_sim:      f64,
    pub flow_sim:          f64,
    pub api_sim:           f64,
    pub tainted_api_sim:   f64,
    pub motif_sim:         f64,
    pub cf_sim:            f64,
    pub has_taint_path:    bool,
    pub pattern_id:        String,
    pub positive_score:    f64,
    pub negative_score:    f64,
    pub final_score:       f64,
}
```

---

## Module: `graph.rs` — `SemanticGraph`

Directed call graph backed by `petgraph::DiGraph<SemanticNode, EdgeKind>`.

```rust
pub enum EdgeKind {
    Calls, RefersTo, OwnedBy, Inherits,
    Overrides, FlowsFrom, SequentiallyFollows,
    InScope, Parameter, TaintFlow,
}

pub struct SemanticGraph {
    graph:       DiGraph<SemanticNode, EdgeKind>,
    name_index:  HashMap<String, Vec<NodeIndex>>,
    taint_flows: Vec<TaintFlowRecord>,
}
```

Built incrementally per-file, merged into a global graph in `analyze_project`. Used by:
- Cross-file taint resolver (BFS over `Calls` edges).
- Consistency checker (find sibling functions sharing a name prefix).
- Temporal analyzer (find `SequentiallyFollows` violations).

---

## Module: `semantic.rs` — `SemanticProvider`

Trait with three concrete implementations:

```
ImportMapProvider  ──  zero cost, import alias heuristics
OxcProvider        ──  Oxc compiler, exact JS/TS types (frensense-providers)
RustHirProvider    ──  rust-analyzer HIR, exact Rust types (frensense-providers)
```

The engine asks the provider: "Is this parameter a taint source?" and "Is this call a dangerous sink?" instead of hardcoding these judgments.

---

## Module: `profile.rs` — `ProjectProfile`

Computes the frequency distribution of n-gram hashes across all functions in a project. Used to compute per-project IDF weights — n-grams that appear in many of the project's functions are down-weighted (they are likely boilerplate, not vulnerability signals).

```rust
pub struct ProjectProfile {
    pub version:   u32,
    pub languages: HashMap<String, LanguageProfile>,
    pub threshold: f64,
}

pub struct LanguageProfile {
    pub total_functions:        usize,
    pub body_ngram_freq:        FxHashMap<u64, ProfileEntry>,
    pub structural_marker_freq: FxHashMap<u64, ProfileEntry>,
    // ...
}
```

---

## Module: `function_role.rs` — `FunctionRole`

A lightweight pre-filter that classifies a function by its role before corpus matching. If the candidate's role is incompatible with a pattern's expected role, scoring is skipped.

```rust
pub enum FunctionRole {
    HttpHandler,      // Express/Fastify/Hono handler: has req/res params, calls res.*
    DbQuery,          // Reads/writes database: calls query/execute/prepare
    ShellExecutor,    // Spawns commands: calls exec/spawn/system
    DataTransformer,  // Pure transformation: no control flow, no API calls
    Unknown,
}
```

Classification uses fingerprint fields only — no AST re-traversal. Zero cost.
