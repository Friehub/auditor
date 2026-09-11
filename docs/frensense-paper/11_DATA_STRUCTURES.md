# Key Data Structures

This document annotates the most important data structures in the codebase — what every field means, why it exists, and what CS concept it serves.

---

## `FunctionFingerprint`

**File:** [`frensense-engine/src/fingerprint/types.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/frensense-engine/src/fingerprint/types.rs)

The central unit of analysis. One instance per function in the codebase (and per function in the corpus). Every matching and scoring operation works on `FunctionFingerprint` pairs.

```rust
pub struct FunctionFingerprint {
    // ── Identity ────────────────────────────────────────────────────────
    pub file_path:     String,        // absolute path of source file
    pub function_name: String,        // as written in source
    pub line:          usize,         // 1-indexed start line
    pub language:      String,        // "typescript", "rust", "javascript", etc.

    // ── N-gram representations ───────────────────────────────────────────
    pub ngram_hashes:           Vec<u64>,               // sorted body token n-gram hashes (w=3,5,8)
    pub weighted_ngram_hashes:  FxHashMap<u64, f32>,    // same, weighted by TF-IDF
    pub signature_ngrams:       Vec<u64>,               // n-grams of the function signature only
    pub param_type_ngrams:      Vec<u64>,               // n-grams of parameter type annotations

    // ── Structural representations ───────────────────────────────────────
    pub structural_markers: Vec<u64>,  // counts of AST kinds: [if_count, loop_count, try_count, ...]
    pub skeleton:           Vec<String>, // ordered structural node sequence (for TED)
    pub skeleton_hashes:    Vec<u64>,    // hashed skeleton (for fast Jaccard)

    // ── Semantic representations ─────────────────────────────────────────
    pub semantic_markers: Vec<u64>,    // hashes of known dangerous API call names
    pub type_usages:      Vec<String>, // type annotation token strings
    pub name_segments:    Vec<String>, // function name split by camelCase/snake_case

    // ── API call representations ─────────────────────────────────────────
    pub api_calls:         Vec<u64>,   // hashes of full callee expressions ("db.query", "exec")
    pub api_call_segments: Vec<u64>,   // last-segment hashes ("query", "exec") — method names only
    pub raw_call_names:    Vec<String>, // literal callee strings (used for cross-file taint update)
    pub motif_hashes:      Vec<u64>,   // canonical motif name hashes (e.g. hash("CommandExecutionSink"))
    pub property_accesses: Vec<u64>,   // hashes of object.property access names

    // ── Data flow representations ─────────────────────────────────────────
    pub data_flow_path_hashes:  Vec<u64>, // abstract source→sink path hashes (variable-renaming invariant)
    pub tainted_api_calls:      Vec<u64>, // API calls where at least one argument is a param (taint source)
    pub control_flow_hashes:    Vec<u64>, // hashed CFG paths (branch enumeration)
    pub control_flow_sequence:  Vec<u64>, // ordered CFG event sequence (for order-sensitive matching)

    // ── Argument/literal representations ─────────────────────────────────
    pub config_literal_hashes:  Vec<u64>, // hashes of configuration-style string literals
    pub argument_call_types:    Vec<u64>, // (function, arg_position, arg_ast_kind) triple hashes
    pub literal_pattern_hashes: Vec<u64>, // patterns in string/template literal call arguments
    pub param_names:            Vec<String>, // parameter names from the function signature

    // ── HTTP handler metadata ─────────────────────────────────────────────
    pub has_http_decorator:     bool,                       // @Get, @Post, @Controller, etc.
    pub is_registered_handler:  bool,                       // app.get(path, fn), router.use(fn)
    pub export_handler_kind:    Option<ExportHandlerKind>,  // CJS: module.exports = fn, etc.

    // ── Comment density ───────────────────────────────────────────────────
    pub comment_density: f64, // comment bytes / total bytes (used for corpus quality gate)
}
```

### Field Group → Scoring Dimension Mapping

| Field group | Scoring dimension | Similarity metric |
|---|---|---|
| `ngram_hashes` | `ngram_sim` | Jaccard |
| `skeleton_hashes` | `ast_sim` | Jaccard |
| `signature_ngrams` | `signature_sim` | Jaccard |
| `param_type_ngrams` | `param_type_sim` | Jaccard |
| `type_usages` | `type_usage_sim` | Jaccard |
| `semantic_markers` | `semantic_sim` | Jaccard |
| `control_flow_hashes` | `cf_sim` | Jaccard |
| `api_calls` + `api_call_segments` | `api_sim` | Jaccard (IDF-weighted) |
| `tainted_api_calls` | `tainted_api_sim` | Jaccard |
| `motif_hashes` | `motif_sim` | Jaccard |
| `data_flow_path_hashes` | `flow_sim` | Jaccard |
| `config_literal_hashes` | `config_sim` | Jaccard |
| `control_flow_sequence` | `cf_order_sim` | Cosine |
| `argument_call_types` | `arg_type_sim` | Jaccard |
| `literal_pattern_hashes` | `literal_concat_sim` | Jaccard |

---

## `PatternRegistry`

**File:** [`frensense-engine/src/corpus/registry.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/frensense-engine/src/corpus/registry.rs)

The matching engine's state. Loaded once from the `.frc` bundle at startup.

```rust
pub struct PatternRegistry {
    patterns:   Vec<CorpusPattern>,            // all loaded corpus patterns

    // ── LSH indexes ────────────────────────────────────────────────────
    lsh_index:     Option<LSHIndex>,           // primary: n-gram hashes
    lsh_index_api: Option<LSHIndex>,           // secondary: API call hashes
    flow_index:    Option<FxHashMap<u64, Vec<usize>>>, // exact: flow path hashes → pattern IDs

    // ── Thresholds ──────────────────────────────────────────────────────
    threshold:               f64,   // minimum final score to emit (default 0.65)
    ngram_sim_threshold:     f64,   // LSH pre-filter minimum (default 0.05)
    struct_overlap_threshold: f64,  // structural overlap minimum

    // ── Per-pattern threshold overrides ─────────────────────────────────
    threshold_overrides: HashMap<String, f64>, // pattern_id → custom threshold

    // ── Learned weights ──────────────────────────────────────────────────
    idf_weights:     FxHashMap<u64, f32>,  // n-gram IDF weights across corpus
    api_idf_weights: FxHashMap<u64, f32>,  // API call IDF weights across corpus

    // Per-category 15-dimensional learned weight vectors
    category_weights: HashMap<String, [f64; 15]>,

    // ── Calibration ──────────────────────────────────────────────────────
    // Per-pattern sigmoid (A, B) parameters for score → confidence mapping
    pattern_calibration: HashMap<String, (f32, f32)>,

    // ── Semantic markers ─────────────────────────────────────────────────
    // Discovered at bundle time: API call name → vulnerability category
    // E.g., "exec" → "cmdi", "db.query" → "sqli"
    learned_semantic_markers: HashMap<String, String>,

    // ── Source/sink registry ─────────────────────────────────────────────
    // Per-corpus sink definitions (from scanning corpus positive files)
    source_sink: CorpusSourceSinkRegistry,

    // ── Scoring configuration ─────────────────────────────────────────────
    scorer_config: ScorerConfig,  // all tunable scoring parameters

    // ── Pattern freshness tracking ───────────────────────────────────────
    // Counts: (total_matches, verified_matches) per pattern
    // Patterns that match many functions but rarely verify taint are penalized
    pattern_freshness: FxHashMap<String, (u64, u64)>,
    freshness_decay:   f64,  // decay factor for stale patterns
}
```

---

## `Advisory`

**File:** [`src/lib.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/src/lib.rs)

The unified finding type. Every detection mechanism — corpus matching, rule checks, taint analysis, temporal checking — produces `Advisory` instances.

```rust
pub struct Advisory {
    pub rule_id: String,              // "CORPUS_TS_SQLI_WHERE", "TAINT_INPUT_TO_EXEC"
    pub file_id: FileId,              // opaque u32 per session (for dedup)
    pub file_path: String,
    pub severity: Severity,           // Critical | Warning | Info
    pub confidence: f64,              // [0, 1] calibrated probability

    // ── Human-readable text (may have {{ source }}/{{ sink }} interpolated) ──
    pub observation: String,
    pub impact:      String,
    pub improvement: String,

    // ── Source location ───────────────────────────────────────────────────
    pub line:   u32,
    pub column: u32,
    pub start_byte: u32,
    pub end_byte:   u32,

    // ── Code context ─────────────────────────────────────────────────────
    pub original_content:    String,           // flagged code snippet
    pub enclosing_symbol:    Option<String>,   // containing function name

    // ── Proposed fix ─────────────────────────────────────────────────────
    pub proposed_replacement: Option<String>,  // auto-fix code
    pub proposed_import:      Option<String>,  // import statement to add

    // ── Deduplication / identity ──────────────────────────────────────────
    pub fingerprint: String,    // content hash (Blake3 of rule_id+file+line+content)
    pub auto_fixable:    bool,
    pub requires_human:  bool,

    // ── Classification ────────────────────────────────────────────────────
    pub tags: Vec<String>,          // e.g., ["taint-verified", "sql", "injection"]

    // ── Composition layer metadata ────────────────────────────────────────
    pub taint_branch_ratio: Option<f64>,     // from TaintMetrics
    pub has_validation_name: Option<bool>,

    // ── Evidence (corpus findings only) ──────────────────────────────────
    pub match_evidence: Option<MatchEvidence>, // per-dimension score breakdown

    // ── Standard security metadata (from [frensense] block) ───────────────
    pub cwe:   Option<String>,  // "CWE-89"
    pub cvss:  Option<f32>,     // 9.8
    pub owasp: Option<String>,  // "A03:2021"
}
```

---

## `RawDimensions`

**File:** [`frensense-engine/src/pattern/similarity.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/frensense-engine/src/pattern/similarity.rs)

The 15-dimensional similarity vector. One instance per (function, pattern) comparison.

```rust
pub struct RawDimensions {
    pub ngram_sim:         f64, // Jaccard of body token n-gram sets
    pub ast_sim:           f64, // Jaccard of structural skeleton hashes
    pub signature_sim:     f64, // Jaccard of function signature n-grams
    pub param_type_sim:    f64, // Jaccard of parameter type annotation hashes
    pub type_usage_sim:    f64, // Jaccard of type usage token sets
    pub semantic_sim:      f64, // Jaccard of semantic marker hashes
    pub cf_sim:            f64, // Jaccard of control flow path hashes
    pub api_sim:           f64, // Jaccard of API call hashes (IDF-weighted)
    pub tainted_api_sim:   f64, // Jaccard of tainted API call hashes
    pub motif_sim:         f64, // Jaccard of semantic motif hashes
    pub flow_sim:          f64, // Jaccard of intra-function flow path hashes
    pub config_sim:        f64, // Jaccard of configuration literal hashes
    pub cf_order_sim:      f64, // Cosine similarity of ordered CFG event sequences
    pub arg_type_sim:      f64, // Jaccard of argument-type triple hashes
    pub literal_concat_sim: f64, // Jaccard of literal content pattern hashes
}
```

Scoring formula:
```rust
pub fn weighted_score(&self, w: &[f64; 15]) -> f64 {
    let identity_gate = self.api_sim.max(self.semantic_sim).max(self.ast_sim)
                            .max(self.motif_sim).max(self.flow_sim);
    let gate = (identity_gate * 2.5 + 0.1).min(1.0);

    let vuln_score = self.ngram_sim * w[0]
        + self.ast_sim * w[1]
        + /* ... all 15 dimensions ... */
        + self.literal_concat_sim * w[14];

    vuln_score * gate
}
```

---

## `TaintRegistry`

**File:** [`frensense-engine/src/data_flow/mod.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/frensense-engine/src/data_flow/mod.rs)

A scope-stack lattice for tracking tainted variables during AST traversal.

```rust
pub struct TaintRegistry {
    // Scope stack: inner = current scope, outer = enclosing scopes
    scopes:        Vec<FxHashMap<String, TaintOrigin>>,          // var → origin
    symbol_ranges: Vec<FxHashMap<String, (usize, usize)>>,       // var → byte range
    field_taint:   Vec<FxHashMap<(String, String), TaintOrigin>>, // (var, field) → origin
}
```

- `push_scope()` / `pop_scope()` — enter/leave a block. Pop is conservative: taint survives scope exit.
- `taint(var, origin)` — mark variable as tainted.
- `untaint(var)` — remove taint (only after unconditional sanitizer).
- `taint_field(var, field, origin)` — field-level granularity (`req.body.userId`).
- `is_tainted(var)` — checks both variable and field taint.
- `get_origin(var)` — retrieve taint origin (enables "what is the source?" in advisories).

---

## `SemanticFilter`

**File:** [`frensense-engine/src/corpus/semantic.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/frensense-engine/src/corpus/semantic.rs)

Pre-match gate checked before any scoring. If any constraint fails, the pattern is skipped — no scoring computation.

```rust
pub struct SemanticFilter {
    // Positive constraints (must be satisfied)
    pub contains_call_to:             Vec<String>, // function body must call these
    pub contains_node_type:           Vec<String>, // body must have these AST kinds
    pub required_taint_flows:         Vec<(String, String)>, // (source, sink) pairs
    pub contains_import:              Vec<String>, // file must import these packages
    pub function_name_regex:          Option<String>,

    // Negative constraints (must NOT be satisfied)
    pub must_not_contain_call_to:           Vec<String>,
    pub must_not_contain_node_type:         Vec<String>,
    pub must_not_contain_import:            Vec<String>,
    pub must_not_match_function_name:       Vec<String>,
    pub must_not_match_file_path_pattern:   Vec<String>,
}
```

---

## `ControlFlowGraph`

**File:** [`frensense-engine/src/cfg/mod.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/frensense-engine/src/cfg/mod.rs)

```rust
pub struct ControlFlowGraph<'a> {
    pub blocks: Vec<BasicBlock<'a>>,
    entry: usize,
    exit:  usize,
    label_index: FxHashMap<String, usize>,
}

pub struct BasicBlock<'a> {
    pub id:         usize,
    pub start_byte: usize,
    pub end_byte:   usize,
    pub kind:       String,                  // "if", "loop", "try", "normal"
    pub nodes:      Vec<Node<'a>>,           // tree-sitter nodes in this block
    pub dominators: FxHashSet<usize>,        // block IDs that dominate this block
    pub successors: Vec<(usize, CFEdgeKind)>,
    pub predecessors: Vec<usize>,
}

pub enum CFEdgeKind {
    Unconditional, // normal sequential flow
    Branch,        // true/false branch of if/switch
    Merge,         // join point after branch
    BackEdge,      // loop back edge
    Exception,     // throw/catch edge
}
```

---

## `SemanticGraph`

**File:** [`frensense-engine/src/graph.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/frensense-engine/src/graph.rs)

```rust
pub struct SemanticGraph {
    graph:       DiGraph<SemanticNode, EdgeKind>, // petgraph adjacency-list directed graph
    name_index:  HashMap<String, Vec<NodeIndex>>, // name → node IDs (multi-valued for overloading)
    taint_flows: Vec<TaintFlowRecord>,            // confirmed taint flow records
}

pub enum EdgeKind {
    Calls,                // A calls B
    RefersTo,             // A references B (not as call)
    OwnedBy,              // method belongs to class
    Inherits,             // class inherits from another
    Overrides,            // method overrides parent method
    FlowsFrom,            // data flow: A's value comes from B
    SequentiallyFollows,  // B is always called after A in same scope
    InScope,              // B is nested inside A's scope
    Parameter,            // B is a parameter of A
    TaintFlow,            // confirmed taint: tainted data flows from A to B
}
```

---

## `CompositionConfig`

**File:** [`src/engine/composition.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/src/engine/composition.rs)

All tunable parameters for the multi-layer AND-gate, documented:

```rust
pub struct CompositionConfig {
    // L2: structural-only penalty (corpus match, no taint confirmation)
    pub taint_unconfirmed_penalty: f64,           // default: 0.6

    // L3: hollow validator suppression
    pub high_branch_ratio_threshold: f64,          // default: 0.85
    pub high_branch_ratio_suppression_factor: f64, // default: 0.3

    // L4: near-duplicate boost
    pub boost_rate: f64, // default: 0.10 — score × (1 + boost_rate)
    pub boost_max:  f64, // default: 0.30 — max absolute lift from L4
}
```

---

## `ScorerConfig`

**File:** [`frensense-engine/src/pattern/scorer.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/Frensense/frensense-engine/src/pattern/scorer.rs)

All scoring constants as named fields — nothing hardcoded in logic.

Selected fields:

```rust
pub struct ScorerConfig {
    // Similarity
    pub empty_similarity_default: f64,    // 0.5 — neutral when both sides are empty
    pub cross_lingual_penalty: f32,       // 0.20 — penalty when pattern lang ≠ file lang
    pub semantic_zero_penalty: f64,       // penalty when zero semantic marker overlap
    pub semantic_match_boost: f64,        // boost when semantic markers match

    // Noise gate
    pub noise_gate_moderate_signal: f64,  // 0.2 — moderate signal threshold
    pub noise_gate_strong_signal: f64,    // 0.4 — strong signal threshold
    pub noise_gate_min_moderate_dims: usize, // minimum moderate-signal dimensions required

    // Negative contrastive
    pub neg_penalty_floor: f64,           // floor for negative penalty
    pub neg_penalty_weight: f64,          // weight of negative similarity

    // Taint verification boost/penalty
    pub taint_verified_boost: f64,        // 1.20 — score × 1.2 when taint confirmed
    pub cross_file_taint_boost: f64,      // 1.15 — score × 1.15 for cross-file taint
    pub taint_boost_cap: f64,             // 0.95 — maximum confidence after taint boost
    pub score_suppression_floor: f64,     // 0.20 — minimum score for untainted matches

    // LSH
    pub lsh_num_hashes: usize,            // 128
    pub lsh_bands: usize,                 // 32
    pub lsh_rows_per_band: usize,         // 8

    // Per-category overrides
    pub category_weight_overrides: FxHashMap<String, [f64; 15]>,
}
```
