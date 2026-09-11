# End-to-End Analysis Pipeline

This document traces a single file through the entire Frensense analysis pipeline from disk to finding.

---

## Pipeline Diagram

```
 ─────────────────────────────────────────────────────────────────────
 INPUT: source directory (e.g., src/)
 ─────────────────────────────────────────────────────────────────────
         │
         ▼
 ┌─────────────────┐
 │  File Walker    │  walkdir: recursive, depth-first
 │  (auditor/)     │  rayon: parallel across files
 └────────┬────────┘
          │ exclude: node_modules/, target/, *.test.*, *.min.js, >1 MB
          │
         ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │  analyze_file(source, language, path, file_id)                  │
 │  frensense-engine/src/lib.rs                                    │
 │                                                                  │
 │  1. tree-sitter parse → CST (concrete syntax tree)             │
 │  2. ImportMap::build_from_tree() → local alias → package map   │
 │  3. HandlerRegistry::build() → route registration map          │
 │  4. fingerprint::extract_fingerprints()                         │
 │     ├── Walk all function/method/arrow nodes                    │
 │     ├── extract ngram_hashes (w=3,5,8 rolling hash)            │
 │     ├── extract structural_markers (if/loop/try counts)        │
 │     ├── extract semantic_markers (dangerous API hashes)        │
 │     ├── extract api_calls, api_call_segments                   │
 │     ├── extract motif_hashes (semantic source/sink groups)     │
 │     ├── extract control_flow_hashes (CFG path enumeration)     │
 │     ├── extract data_flow_path_hashes (flow_fingerprint.rs)    │
 │     └── extract tainted_api_calls (param→api-call links)       │
 │  5. SymbolRegistry::extract_from_tree() → symbol table        │
 │  6. SemanticExtractor::extract() → Vec<SemanticOp>            │
 │     (normalized IR: Binding, Assignment, Call, Return)          │
 │  7. SemanticGraph construction (full-analysis feature)         │
 │  8. temporal_events extraction                                  │
 └────────────────────────────┬────────────────────────────────────┘
                               │
                               ▼ AnalysisResult per file
 ┌─────────────────────────────────────────────────────────────────┐
 │  analyze_project() — cross-file pass                           │
 │  frensense-engine/src/lib.rs                                    │
 │                                                                  │
 │  1. Merge all SemanticGraphs → global_graph                    │
 │  2. cross_file::build_resolver(symbols, graph)                 │
 │  3. Seed HTTP handlers as TaintOrigin::UserInput sources        │
 │  4. resolver.propagate_taint(None) — BFS over Calls edges       │
 │  5. For DbQuery/ShellExecutor functions:                        │
 │     resolver.resolve_taint(fn_name, file, depth=10)            │
 │     → if tainted: update fingerprint.tainted_api_calls         │
 │  6. Return-value taint propagation:                             │
 │     let result = dbQuery() → mark 'result' as tainted binding  │
 │  7. Second pass: update is_registered_handler via project       │
 │     route registry (cross-file route registrations)            │
 └────────────────────────────┬────────────────────────────────────┘
                               │
                               ▼ ProjectAnalysis
 ┌─────────────────────────────────────────────────────────────────┐
 │  Engine.scan() — per function, per file                        │
 │  src/engine/auditor/                                            │
 │                                                                  │
 │  For each file, for each function fingerprint:                  │
 │                                                                  │
 │  A. FunctionRole classification (zero cost, fingerprint-only)   │
 │     → HttpHandler / DbQuery / ShellExecutor / DataTransformer   │
 │                                                                  │
 │  B. SemanticFilter pre-check (O(1) per pattern)                 │
 │     → skip pattern if contains_call_to not satisfied           │
 │     → skip pattern if must_not_contain_import violated         │
 │     → skip if function_name_regex doesn't match               │
 │                                                                  │
 │  C. LSH Candidate Retrieval                                    │
 │     1. minhash_signature(ngram_hashes, 120 hashes)             │
 │     2. Query 40 LSH bands → union of matching pattern IDs      │
 │     3. Also query lsh_index_api (API call hashes)              │
 │     4. Also query flow_index (exact flow path hashes)          │
 │     → candidate_set: typically 0-20 patterns                   │
 │                                                                  │
 │  D. 15-Dimensional Scoring (per candidate pattern)             │
 │     1. Compute RawDimensions:                                   │
 │        ngram_sim, ast_sim, signature_sim, param_type_sim,       │
 │        type_usage_sim, semantic_sim, cf_sim, api_sim,           │
 │        tainted_api_sim, motif_sim, flow_sim, config_sim,        │
 │        cf_order_sim, arg_type_sim, literal_concat_sim           │
 │     2. identity_gate = max(api_sim, semantic_sim, ast_sim,      │
 │                             motif_sim, flow_sim)                │
 │        gate = min(identity_gate * 2.5 + 0.1, 1.0)             │
 │     3. vuln_score = Σ (dim_i * weight_i), gated by gate        │
 │     4. Contrastive: score vs. negative fingerprints            │
 │        final = pos_score - neg_penalty_weight * neg_score       │
 │     5. Profile boost (rare n-grams in this codebase)           │
 │     6. Cross-lingual penalty (if pattern lang ≠ file lang)     │
 │     7. Sigmoid calibration: σ(A * score + B)                   │
 │                                                                  │
 │  E. Threshold gate: discard if score < threshold (default 0.65) │
 │                                                                  │
 │  F. Taint Verification (DataFlowEngine)                        │
 │     → Walk function AST with TaintRegistry                     │
 │     → tag = "taint-verified" if source→sink path confirmed     │
 │     → score boost ×1.2 if verified; penalty ×0.6 if not        │
 │                                                                  │
 │  G. Advisory emission                                           │
 │     → Interpolate {{ source }}, {{ sink }} in observation text  │
 │     → Attach MatchEvidence (per-dimension breakdown)           │
 │     → Attach CWE/CVSS/OWASP from pattern metadata             │
 │                                                                  │
 │  H. Rule-based checks (parallel to corpus pipeline)            │
 │     → FrensenseRule.check() for all registered rules           │
 │     → Temporal property checks (event sequence verification)   │
 └────────────────────────────┬────────────────────────────────────┘
                               │
                               ▼ raw Advisory list
 ┌─────────────────────────────────────────────────────────────────┐
 │  Post-Processing                                                │
 │  src/engine/composition.rs + findings/                         │
 │                                                                  │
 │  1. apply_composition() — AND-gate multi-layer confidence:      │
 │     ├── L1∧L2 (corpus + taint): full confidence                │
 │     ├── L1 only: ×0.6 penalty                                  │
 │     ├── L3: validator suppression (ratio>0.85 + name): ×0.3   │
 │     └── L4: near-duplicate boost ×1.1, cap at +0.30           │
 │                                                                  │
 │  2. Deduplication: (rule_id, file, line) → one advisory        │
 │                                                                  │
 │  3. Baseline suppression:                                       │
 │     → Load .frensense-suppress.yml                              │
 │     → Remove advisories matching suppression entries           │
 │                                                                  │
 │  4. Threshold filtering:                                        │
 │     → Apply --severity flag                                    │
 │     → Apply --min-confidence flag                              │
 │     → Apply --strict flag (Critical only)                      │
 └────────────────────────────┬────────────────────────────────────┘
                               │
                               ▼ filtered Advisory list
 ┌─────────────────────────────────────────────────────────────────┐
 │  Reporter                                                       │
 │  src/reporter.rs                                                │
 │                                                                  │
 │  → terminal: colored ANSI output with code snippet context      │
 │  → --json: Advisory structs serialized to JSON array           │
 │  → --sarif: SARIF 2.1.0 with CodeFlow + MatchEvidence          │
 │  → --baseline: emit baseline.json for future suppression        │
 └─────────────────────────────────────────────────────────────────┘
 OUTPUT: findings / exit code 0 (clean) or 1 (findings)
```

---

## Parallelism Model

Frensense uses `rayon` for data-parallel work at three levels:

| Level | What Is Parallelized | Granularity |
|---|---|---|
| File level | `analyze_file()` per file | Per CPU core |
| Corpus matching | `score_against()` per pattern candidate | Per function |
| Rule dispatch | `rule.check()` per rule | Per node (small) |

The `TaintCache` uses `RefCell` (not `Mutex`) because it is only accessed from one thread at a time per file. Cross-file state (the global `SemanticGraph`) is built sequentially after parallel file analysis completes.

---

## Data Flow Invariants

These invariants hold at each stage:

| Stage | Invariant |
|---|---|
| After `analyze_file` | Every function has a complete `FunctionFingerprint`. No cross-file state is consulted. |
| After `analyze_project` | `tainted_api_calls` may be updated for sink functions reachable from HTTP handlers. `is_registered_handler` is accurate project-wide. |
| After corpus scan | Every emitted `Advisory` has `confidence > threshold` and a non-empty `match_evidence`. |
| After composition | `confidence` may be lower than after scoring but never higher than `1.0`. |
| After dedup | At most one `Advisory` per `(rule_id, file_path, line)` tuple. |

---

## Failure Modes

| Failure | Behavior |
|---|---|
| Parse error (malformed source) | Skip file, log warning, continue |
| Unsupported language | Skip file silently |
| Bundle load failure | Fatal error, exit 1 |
| Bundle checksum mismatch | Fatal error, exit 1 (corrupted bundle) |
| Individual rule panic | Catch unwind, skip rule for this file, log error |
| Taint walk timeout | Abort taint walk, emit advisory without "taint-verified" tag |
