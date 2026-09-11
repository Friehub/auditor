# Root Crate: `frensense` — CLI, Orchestration, and MCP Server

**Path:** `src/`  
**Role:** The user-facing layer. Wires all crates together, provides the CLI, manages scan orchestration, and exposes the MCP JSON-RPC server.

---

## `src/lib.rs` — Public API Layer

The root lib exports the types and traits shared across all rule implementations.

### `FrensenseRule` Trait

The core interface every detection rule must implement:

```rust
pub trait FrensenseRule: Send + Sync {
    /// Rule identity and display metadata.
    fn metadata(&self) -> &RuleMetadata;

    /// Per-AST-node check. Called for every node matching the rule's query.
    fn check<'a>(&self, node: Node<'a>, context: &FrensenseContext<'a>) -> Vec<Advisory>;

    /// Which file extensions does this rule apply to?
    fn applies_to(&self, extension: &str) -> bool;

    /// File-level check. Called once per file. Default: no-op.
    fn file_check(&self, context: &FrensenseContext<'_>) -> Vec<Advisory> { vec![] }

    /// Optional tree-sitter query string for efficient node selection.
    fn query(&self) -> Option<&str> { None }

    // --- DRY helpers (implemented on the trait) ---
    fn new_advisory(&self, node: &Node, context: &FrensenseContext, observation: String) -> Advisory;
    fn new_remediated_advisory(...) -> Advisory;
}
```

**CS Theory:** Visitor pattern — rules visit AST nodes via the `check` callback. The engine dispatches each node to all applicable rules, collecting advisories.

### `Advisory` — A Single Finding

The unified finding type. Carries full provenance:

```rust
pub struct Advisory {
    pub rule_id:             String,         // "CORPUS_TS_SQLI_WHERE" or "TAINT_INPUT_TO_EXEC"
    pub file_id:             FileId,         // opaque u32 per analysis session
    pub file_path:           String,
    pub severity:            Severity,       // Critical | Warning | Info
    pub confidence:          f64,            // [0, 1] calibrated probability
    pub observation:         String,         // what was found (human-readable)
    pub impact:              String,
    pub improvement:         String,
    pub line:                u32,
    pub column:              u32,
    pub start_byte:          u32,
    pub end_byte:            u32,
    pub original_content:    String,         // the flagged code snippet
    pub proposed_replacement: Option<String>, // auto-fix suggestion
    pub proposed_import:     Option<String>,  // import to add for fix
    pub enclosing_symbol:    Option<String>,  // containing function name
    pub fingerprint:         String,          // content hash for dedup
    pub auto_fixable:        bool,
    pub requires_human:      bool,
    pub tags:                Vec<String>,
    pub taint_branch_ratio:  Option<f64>,    // from TaintMetrics
    pub has_validation_name: Option<bool>,
    pub match_evidence:      Option<MatchEvidence>, // per-dimension breakdown
    pub cwe:                 Option<String>,  // "CWE-89"
    pub cvss:                Option<f32>,    // 9.8
    pub owasp:               Option<String>, // "A03:2021"
}
```

### `FrensenseContext<'a>` — Analysis Context

Passed to every rule's `check` call. Contains everything a rule might need:

```rust
pub struct FrensenseContext<'a> {
    pub file_id:          FileId,
    pub file_path:        &'a Path,
    pub source_code:      &'a str,
    pub tree:             &'a tree_sitter::Tree,
    pub symbols:          &'a SymbolRegistry,
    pub graph:            &'a SemanticGraph,
    pub semantic_ops:     &'a [SemanticOp],
    pub taint_cache:      &'a TaintCache,
    pub file_trees:       &'a FileTreeMap,    // all project files' parse trees
    pub file_context:     FileContext,        // RouteHandler, Library, Test, etc.

    // Taint analysis tuning
    pub taint_confidence_interprocedural: f64,  // default 0.80
    pub taint_confidence_intraprocedural: f64,  // default 0.90
    pub default_taint_max_depth:          usize, // default 5
    pub ngram_window_size:                usize, // default 5
}
```

`for_interprocedural()` creates a derived context for cross-file analysis, inheriting taint parameters from the parent while pointing to a different file.

### `TaintCache` — LRU Cache for Taint Results

Bounded LRU cache (capacity 1024) preventing redundant taint walks on large files:

```rust
type TaintCacheKey = (String, String, String, String, usize);
// (source_var, sink_call, file_path, function_name, max_depth)

pub struct TaintCache {
    inner: RefCell<HashMap<TaintCacheKey, Vec<Advisory>>>,
    order: RefCell<VecDeque<TaintCacheKey>>,
}
```

Uses `RefCell` for interior mutability — the cache is logically immutable from the rule's perspective (reading it shouldn't require `&mut self`).

---

## `src/engine/` — Scan Orchestration

### `auditor/` — `FrensenseAuditor`

The top-level scanner. Core API:

```rust
pub struct FrensenseAuditor {
    rules:            Vec<Box<dyn FrensenseRule>>,
    corpus_registry:  Option<PatternRegistry>,
    config:           AuditorConfig,
}

pub struct ScanResult {
    pub advisories: Vec<Advisory>,
    pub files_scanned: usize,
    pub duration: Duration,
}

impl FrensenseAuditor {
    pub fn scan_project(&self, project_path: &Path) -> ScanResult;
    pub fn scan_file(&self, path: &Path, source: &str) -> Vec<Advisory>;
}
```

**File walking:** Uses `walkdir` for recursive directory traversal with exclusion rules (test files, build dirs, large files). Files are dispatched to `rayon`'s thread pool for parallel scanning.

**Rule dispatch:** For each file, for each AST node, for each applicable rule — call `rule.check(node, context)`. Collect all advisories.

**Corpus scanning:** Simultaneously, the `PatternRegistry::scan_function` pipeline runs for each fingerprinted function.

**Post-processing:**
1. `apply_composition()` — multi-layer confidence adjustment.
2. Deduplication — same rule_id + file + line collapses to one.
3. Baseline suppression — advisories matching `.frensense-suppress.yml` entries are removed.
4. Severity/confidence filtering — apply `--severity` and `--min-confidence` thresholds.

### `composition.rs` — Multi-Layer AND-Gate

Implements the 4-layer confidence composition model:

```
Layer 1 (L1): Corpus match
Layer 2 (L2): Taint flow confirmed
Layer 3 (L3): Validator suppression (high branch ratio + validator name)
Layer 4 (L4): Near-duplicate boost
```

```rust
pub fn compose_confidence(signals: &LayerSignals, base_score: f64, config: &CompositionConfig) -> f64 {
    let mut score = base_score;

    // L1 + L2: full corroboration → no penalty
    // L1 only: structural-only match → down-weight by 0.6
    if signals.corpus_match && !signals.taint_flow {
        score *= config.taint_unconfirmed_penalty; // default 0.6
    }

    // L3: suppress only genuine validators (not IDOR-style branching functions)
    if let Some(ratio) = signals.taint_branch_ratio
        && ratio > config.high_branch_ratio_threshold  // default 0.85
        && signals.has_validation_name
    {
        score *= config.high_branch_ratio_suppression_factor; // default 0.3
    }

    // L4: near-duplicate boost (capped at boost_max = 0.30)
    if signals.near_duplicate {
        score = (score * (1.0 + config.boost_rate)).min(score + config.boost_max);
    }

    score.min(1.0)
}
```

**CS Theory:** Evidence combination, Bayesian updating (deterministic rule approximation), AND-gate multi-layer verification.

### `learn.rs` — Pattern Learning

Implements `learn_pattern(positive_path, negative_path, pattern_id, output_dir)`:

1. Read positive and negative source files.
2. Run `diff_ast()` — tree-sitter AST diff to identify what changed between positive and negative.
3. `extract_patterns_from_diff()` — generate pattern metadata from the diff structure.
4. Infer `expected_context` from the positive file's path and imports.
5. Copy the files to `output_dir` with the standard naming convention.

This enables the `frensense --learn` command: a developer provides a bug/fix pair and Frensense generates the corpus entry automatically.

### `clustering.rs` — Near-Duplicate Detection

Detects functionally near-duplicate functions within the same project — functions that share the same vulnerability but differ only in variable names or minor structural variations. Near-duplicates boost each other's confidence (L4 in the composition model).

Uses MinHash Jaccard similarity across `ngram_hashes` fields. Two functions with `J > 0.85` are considered near-duplicates.

### `ast_diff.rs` — AST-Level Diff

Computes a semantic diff between two source files using tree-sitter parse trees. Unlike `git diff` (line-based), this captures structural changes: "a conditional branch was added," "a sanitizer call was inserted," "the function signature parameter changed from `string` to `sanitized_string`."

Used by `learn.rs` to understand what the fix changed, enabling automatic metadata generation.

---

## `src/semantics/` — Semantic Rule Implementations

### `simple_taint.rs` — Intraprocedural Taint Rule

```
Rule ID: TAINT_*
Scope: single file
```

Walks a function's AST, tracks taint with `TaintRegistry`, and emits an advisory when tainted data reaches a sink. Generates rule IDs like `TAINT_INPUT_TO_EXEC`, `TAINT_INPUT_TO_SQL`.

### `consistency.rs` — Cross-Function Consistency Checker

```
Rule ID: CONSISTENCY_*
Scope: cross-function within a file
```

Identifies groups of sibling functions (same name prefix, e.g., `handleUserCreate`, `handleUserUpdate`, `handleUserDelete`) and checks whether they apply the same security patterns consistently. If `handleUserCreate` validates ownership but `handleUserUpdate` does not, this is a `CONSISTENCY_OWNERSHIP` finding.

**CS Theory:** Program consistency analysis, cross-function property checking, ownership invariant verification.

### `data_flow/` — Interprocedural Taint

```
Rule ID: CROSS_FILE_TAINT
Scope: cross-file
```

Uses the `analyze_project` cross-file resolver to find taint paths that span multiple files (e.g., HTTP handler → service layer → repository → raw SQL query).

---

## `src/temporal/` — Temporal Property Checker

### `analyzer.rs`

Checks event sequence properties against the actual ordered sequence of API calls in a function:

```rust
pub struct TemporalRule {
    pub id: String,
    pub sequence: Vec<String>,    // required call sequence
    pub behavior: String,          // human description of the invariant
    pub severity: Severity,
}
```

For each function, extract the ordered sequence of matching API calls and verify the temporal rule's sequence is satisfied (subsequence check). Failure emits a `TEMPORAL_*` advisory.

### `config.rs` — Built-in Temporal Rules

Hardcoded rules for financial operations (largest and most risky domain):

| Rule | Sequence | Invariant |
|---|---|---|
| Fund + Ledger | `fundWallet → createLedgerEntry` | Every credit must journal |
| Debit + Ledger | `debitWallet → createLedgerEntry` | Every debit must journal |
| Payment Gate | `checkPaymentGate → fundWallet` | Credit only after payment verified |
| Auth before Transfer | `verifyAuth → transferFunds` | Transfer requires auth |

**CS Theory:** Linear temporal logic (LTL), `G(A → F(B))` pattern restricted to function scope, sequence property verification.

---

## `src/mcp/` — Model Context Protocol Server

### Architecture

The MCP server exposes Frensense's analysis capabilities to AI agents (Claude, Antigravity, Cursor) over a `stdio` JSON-RPC channel following the Model Context Protocol specification.

```rust
// protocol.rs
pub struct McpRequest {
    pub jsonrpc: String,  // "2.0"
    pub method: String,
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

pub struct McpResponse {
    pub jsonrpc: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<McpError>,
    pub id: serde_json::Value,
}
```

### Exposed Methods

| Method | Description |
|---|---|
| `frensense/scan` | Scan a path and return findings as JSON |
| `frensense/taint` | Resolve taint path for a specific function |
| `frensense/validate` | Validate a code snippet against the corpus |
| `frensense/patterns` | List loaded corpus patterns |
| `frensense/suggest` | Suggest a fix for a given advisory |

### Use Case

AI agents generating code can call `frensense/validate` before committing a change to check if the generated code matches any known vulnerability patterns. This closes the loop: the same engine that finds bugs in human code can also vet AI-generated code in real time.

---

## `src/reporter.rs` — Output Formatters

Three output formats:

| Format | Flag | Use Case |
|---|---|---|
| Terminal ANSI | (default) | Human review, CI logs |
| JSON | `--json` | Programmatic consumption, dashboards |
| SARIF 2.1.0 | `--sarif` | GitHub Advanced Security, VS Code Problems pane |

The SARIF output includes `MatchEvidence` as SARIF `CodeFlow` entries, making the per-dimension score breakdown visible in the GitHub security tab.
