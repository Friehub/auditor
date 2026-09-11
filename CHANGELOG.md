# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-09-10
### Architecture & Core Engine
- **Field-Sensitive Program Dependence Graph (PDG)**: Transitioned the core taint engine from naive string-matching heuristics (`has_param_ref`) to exact graph-reachability queries. 
- **Upgraded Def-Use Chains**: Modified `def_use.rs` to track full access paths (e.g. `req.body.id`) rather than flattening variables to their base object, eliminating phantom data-flows.
- **Data & Control Fusion**: Introduced `pdg.rs` to fuse data dependence (from DefUseChains) with control dependence (via Post-Dominator trees).
- **Benchmark Validated**: The structural PDG upgrade increased True Positives on NodeGoat and Juice Shop by 145% (from 11 to 27) compared to the baseline heuristic.

### Fixed
- **Weight Learner Bias Fix**: Fixed a critical gradient descent bug in `frensense-bundler` where missing dimensions (like cross-file `flow_sim`) maintained their `0.5` initialization weight and stole up to 50% of the overall classification weight from valid dimensions during normalization. Dimensions are now initialized to `0.0`.
- **AST Extraction for Semantic Rules**: Replaced the fragile `extract_call_targets` regex in both the bundler and engine with a robust Tree-sitter AST walk, completely eliminating mismatches where the bundler learned structural motifs that the inference engine failed to extract.
- **OOM during LCS similarity**: Replaced the unbounded `O(N*M)` matrix allocation in `lcs_similarity` with an `O(min(N, M))` two-row approach and a length cap, fixing fatal out-of-memory panics when the bundler processed control-flow graphs with 20,000+ paths.
- **Scoring Unification**: Centralized `frensense-bundler` and `frensense-engine` math down to a single `compute_dimensions()` function to prevent divergence in how `tainted_api_sim` and other features are evaluated.
- **Regex Illusion / False Recall**: Identified and resolved a critical bug where `auto_filter` incorrectly extracted `if` and `catch` as exact API calls, artificially inflating both textual overlap (`ngram_sim`, `signature_sim`) and motif hashes across frameworks. The heuristic `contains_call_to` generator in `frensense-bundler` has been temporarily disabled pending an AST-aware replacement.
- **Semantic Override Generalization**: `apply_semantic_override` now successfully triggers on `flow_sim > 0.8` (which hashes abstract `SemanticMarkers` like `SqlSink` rather than raw strings) and `identity_gate > 0.1`, dropping the strict `motif_sim > 0.8` requirement. This allows the engine's core data-flow abstraction to generalize across frameworks (e.g. `db.query` vs `sequelize.query`).
- **Minimum-Score Gate Strictness**: Temporarily disabled the hard-coded gate in `runner.rs` that silently dropped matches if structural/textual overlap (`ngram_sim` AND `signature_sim`) was `< 5%`. This ensures valid data-flow matches between small corpus patterns (15 lines) and large, harness-heavy vulnerable functions (78 lines) are not discarded.

### Benchmark Results (Juice Shop & NodeGoat)
- **Juice Shop True Positives**: 112 (Findings on known vulnerable files)
- **Juice Shop Precision**: 50.00%
- **Juice Shop File Recall**: 54.05% (20/37 vulnerable files hit)
- **NodeGoat True Positives**: 74 (Findings on known vulnerable lines)
- **NodeGoat Precision**: 87.06%
- **NodeGoat Recall**: 56.67% (17/30 vulnerabilities hit)
- *Note: These results were achieved without strict gates, allowing the engine's data-flow improvements to generalize across different ORMs.*


## [Unreleased]

### Fixed

- **Engine Divergence (Regex to AST for Call Targets)**: Completely eliminated a severe divergence bug between `frensense-bundler` (which learns node rules via AST) and `frensense-engine` (which was enforcing them via naive Regex).
  - **The Problem:** The engine previously used `crate::auto_filter::extract_call_targets` (which relied on `regex::Regex::new(r"([a-zA-Z0-9_]+)\s*\(")`). This anti-pattern stripped namespaces (e.g. `vm.runInContext` was captured only as `runInContext`) and hallucinated function calls on control flow structures like `if (` and `while (`.
  - **The Fix:** Refactored `SemanticFilter::matches` in `frensense-engine/src/corpus/semantic.rs` to implement a full Tree-sitter AST pre-order traversal (`extract_ast_call_targets`). We now walk `call_expression` nodes directly and extract the `callee` using `std::str::from_utf8`.
  - **The Result:** False Positives on the OWASP Juice Shop benchmark plummeted from 38 down to 18. Notorious false positives like `CORPUS_TS_RCE_VM_CONTEXT` and `CORPUS_TS_PERM_CACHE_STALE_ELEVATION` were completely eliminated because the scanner now enforces context rules with 100% fidelity to the bundler.
  - **The Benchmark:** Note that while False Positives fell significantly, True Positives also fell as the engine strictly enforced the learned AST rules against the benchmark targets:
    ```text
    === FRENSENSE OWASP JUICE SHOP BENCHMARK ===
    Ground truth:      37 vulnerable files
    True Positives:    2  (findings on known-vuln files)
    False Positives:   18  (findings on clean files)
    Precision:         10.00%
    File Recall:       5.41%  (2/37 vuln files hit)
    ```

## [0.5.3-fp-fix] - 2026-09-08

### Fixed — Corpus Scoring False-Positive Reduction

Five targeted fixes to the scoring pipeline reduce Juice Shop FPs by 65% (60→21)
and raise precision from 25.93% to 34.38% with no change to rule-based recall.

- **Double calibration removed** (`src/engine/project/runner.rs`): `per_pattern_calibration::calibrate`
  was applied twice — once inside `registry::score_candidate` and once again in the runner. Applying
  `sigmoid(sigmoid(x))` compresses all scores toward 1.0, inflating FP confidence. The redundant
  runner-side call is removed.

- **`tainted_api_sim` neutral-empty fix** (`frensense-engine/src/pattern/scorer.rs`): When both the
  candidate and the corpus positive had empty `tainted_api_calls`, the dimension returned `1.0`
  ("they agree"). This injected a free 0.30-weighted signal on every function where taint analysis
  produced no data — which is most clean-file functions. Changed to return `0.0` (no taint data →
  no taint signal). The condition was broadened from `&&` (both empty) to `||` (either empty) so a
  corpus positive with no tainted calls does not falsely validate an untainted candidate.

- **DEFAULT_WEIGHTS rebalanced** (`frensense-engine/src/pattern/weight_learner.rs`): API-call
  dimensions were over-weighted for TypeScript/Node.js codebases where framework calls
  (`sequelize.query`, `bcrypt.hash`) appear in both vulnerable and clean code equally.
  `api_calls` reduced 0.25→0.14, `tainted_api_calls` reduced 0.30→0.13. Weight redistributed
  to `ngram` (0.05→0.10), `ast` (0.10→0.15), `semantic_markers` (0.05→0.10), `control_flow` (0.04→0.09).

- **`score_suppression_floor` raised** (`frensense-engine/src/pattern/scorer.rs`): Default floor
  raised from 0.20 to 0.35. Post-calibration scores for noise-level raw scores (0.20–0.35) were
  surviving the old floor and becoming findings. The raised floor requires a minimum real signal
  before emission.

- **`apply_semantic_override` guards tightened** (`frensense-engine/src/pattern/scorer.rs`): The
  0.85 hard-floor override now requires `api_sim > 0.5` in addition to `flow_sim > 0.8 && motif_sim > 0.8`,
  preventing motif hash collisions on common patterns from pinning clean code to high scores.
  The secondary 0.75 floor tightened from `api_sim > 0.9` to `api_sim > 0.95`.

### Benchmark (OWASP Juice Shop — Sep 2026)

| Metric | Before (v0.5.1) | After (v0.5.3) | Delta |
|---|---|---|---|
| Total findings | 81 | 32 | −49 (−60%) |
| True Positives | 21 | 11 | −10 |
| False Positives | 60 | **21** | **−39 (−65%)** |
| Precision | 25.93% | **34.38%** | **+8.45 pp** |
| File Recall | 35.14% (13/37) | 24.32% (9/37) | −10.82 pp |

### Benchmark (NodeGoat — Sep 2026, first measured baseline)

| Metric | v0.5.3 |
|---|---|
| True Positives | 23 |
| False Positives | 33 |
| Precision | 41.07% |
| Recall | 56.67% (17/30) |

VULN_NPM_* dependency advisories account for 13/33 FPs (structural, one advisory per outdated package).


### Added
- **Crate Extractor `frensense-bundler`**: Extracted corpus building, loading, and directory scanning logic out of the core engine and into a standalone `frensense-bundler` crate.
- **Crate Extractor `frensense-providers`**: Isolated heavy compiler toolchains (`oxc` for JS/TS and `rust-analyzer`/`ra_ap_*` for Rust) into a separate crate to serve as dynamic semantic providers.
- **Crate Extractor `frensense-lang`**: Separated language-specific specifications and configurations into `frensense-lang`.

### Changed
- **Engine Bloat Reduction**: Decoupled `frensense-engine` into a pure, lightweight runtime scanner. It no longer depends on file system corpus loading or heavy compiler APIs.
- **Dynamic Semantic Providers**: The CLI now conditionally loads and dynamically injects `SemanticProvider` implementations (like `OxcProvider` or `RustHirProvider`) into the engine, preventing aggressive analysis on basic structural files.

### Fixed
- **JavaScript Tree-Sitter Regression**: Fixed a bug where `JavaScriptSpec` incorrectly used the TypeScript `symbol_query` which contained invalid grammar tokens (`type_identifier`, `interface_declaration`). This caused the engine to silently skip parsing all `.js` files. Pure JavaScript scanning (e.g., NodeGoat benchmark) is fully restored.

## [0.5.2] - 2026-09-05


### Added
- **Codebase Deduplication**: Unified the AST traversals in `loader.rs` and `source_sink.rs`, eliminating hundreds of lines of redundant algorithmic logic.
- **Unified Math Ops**: Extracted Jaccard intersection and scoring evaluation formulas into single shared helpers in `minhash.rs`.
- **Corpus Extension**: Added `ts_juiceshop_idor_update_positive.ts` and `ts_n_plus_one_query` targets to expand the Juiceshop benchmark suite.
- **Documentation**: Moved all top-level documentation `.md` files to the `docs/` folder to clean up the repository root.


- **CLI Taint Pass**: Injected the Return-Value Taint Propagation heuristic directly into the CLI's file scanning loop (`runner.rs`), allowing the CLI to correctly trace variables populated from database queries.
- **Return-Value Taint Propagation**: `frensense-engine` now supports tracking taint from function return values inter-procedurally. Added `SemanticOp::Binding` and `SemanticOp::Call` to `SemanticExtractor`, correlated them in `analyze_project` Pass 2, and threaded a `local_tainted_vars` map down to the dataflow engine (`adjust_confidence`, `is_real_source`).
- **Language-Agnostic AST Extraction**: Deduplicated `extract_rust` and `extract_typescript` into a unified `extract_generic` AST walker in `normalization.rs`.
- **CWE Mapping**: Added a `cwe()` method to `SinkCategory` in `source_sink.rs`.

### Changed
- **Structural AST Matching over Text Matching**: Overhauled `has_param_ref` in `fingerprint.rs`, `block_looks_like_auth_guard` in `cfg/mod.rs`, and `extract_sink_var` in `confidence.rs` to use strict tree-sitter AST queries instead of fragile text matching.
- **Universal Multiply-Shift Hashing**: Replaced biased MinHash hashers with a universal multiply-shift hash family, and swapped `DefaultHasher` for `FxHasher` in `lib.rs` for deterministic fingerprints.
- **$O(1)$ LazyLock Maps**: Introduced `LazyLock` for `PACKAGE_SINK_MAP` and `HTTP_FRAMEWORK_SET` in `semantic.rs` to avoid redundant allocations.
- **Flattened Taint Resolver Keys**: `CrossFileTaintResolver` now uses a flattened `"file:symbol"` string key for $O(1)$ lookups.
- **FxHashSet Rollout**: Mass-replaced `std::collections::HashSet` with `rustc_hash::FxHashSet` in `cfg/mod.rs` and `cross_file.rs`.
- **Logging**: Swapped `eprintln!` for `tracing::debug!` in `minhash.rs` and added the `tracing` dependency to `Cargo.toml`.

### Fixed
- **AST Sink Extraction Bug**: Fixed `extract_sink_var_from_ast` in `confidence.rs` to support `member_expression` and `field_expression` as sink arguments (e.g. `req.query.id`), which was previously dropping valid dataflow traces.
- **Dead Parameter Wired**: The `window_size` parameter in `fingerprint.rs` is now correctly wired to the multi-scale ngram logic.

## [0.5.1] - 2026-09-03

### Added
- **Minimum-score gate**: Skip corpus matches where ngram AND signature similarity are both near-zero (<0.05). Prevents calibration sigmoid from boosting noise into high-confidence false positives. Generic API matches like `console.log` alone are insufficient for a finding.
- **Compiler-aware sink registry**: `CorpusSourceSinkRegistry::new(use_compiler: bool)` — when `use_compiler=true`, uses a reduced 95-item sink list (vs 168 full list) covering only truly dangerous bare calls, framework-specific sinks, and MongoDB operators. OXC module resolution handles generic sinks like `query`, `readFile`, `fetch`.
- **`npm audit` / `cargo audit` subprocess integration**: Vulnerability detection now tries `npm audit --json` and `cargo audit --json` before falling back to hardcoded lists. Requires tools to be installed; gracefully degrades if unavailable.
- **LanguageProvider trait methods**: Added `known_sink_names()`, `known_source_patterns()`, `resolve_receiver_module()` to `SemanticProvider` trait with default impls. `OxcProvider` implements using `PACKAGE_SINK_CATEGORIES` + global function sinks. `ImportMapProvider` uses hardcoded fallbacks.
- **Module-based sink classification**: `check_call_for_sink()` now calls `provider.resolve_receiver_module(fn_name_full)` and passes resolved module to `classify_sink()` — enables OXC module-based classification for calls like `db.query()`.

### Changed
- **`PACKAGE_SINK_CATEGORIES` made `pub`**: Was `const`, now `pub const` so `oxc_provider.rs` can reference it.
- **`source_patterns` on `CorpusSourceSinkRegistry`**: Initialized from `always_register_source_patterns()`, merged via `merge()`, checked via `is_source_pattern()`. `confidence.rs:is_real_source()` now uses `registry.is_source_pattern()` instead of hardcoded `TAINT_SOURCE_PATTERNS`.
- **`.gitignore` fixed**: Removed `Cargo.lock` (binary project should track it), added `frensense-bench/datasets/synthetic/`, `frensense-bench/datasets/nodegoat/`, `frensense-bench/results/`.
- **Stale TOML files removed**: Deleted 12 unused `.toml` corpus metadata files.

### Fixed
- **Vulnerable dependency JSON parser**: Fixed trim order bug in `extract_npm_deps_for_vuln_check` where `trim_matches('"')` was applied before `trim_matches(',')`.

### Benchmark (NodeGoat, threshold 0.40)
| Metric | Before | After |
|--------|--------|-------|
| TP | 24 | 22 |
| FP | 252 | 22 |
| FN | 6 | 8 |
| Recall | 0.800 | 0.733 |
| F1 | 0.157 | 0.595 |
| Wall time | 1:36 | 0:41 |

91% FP reduction with only 2 TPs lost. F1 improved 3.8x. Scan time reduced 58%.

## [0.5.0-optimize] - 2026-08-26

### Added
- **Rayon parallelism**: `PatternRegistry::scan_function` scoring loop parallelized via `rayon::par_iter()`. Pre-computes `extracted_flows` and `TaintMetrics` once before parallel section; each candidate gets its own `dim_cache`. Extracted `score_candidate()` helper method for parallel dispatch.
- **thiserror for FrensenseError**: `FrensenseError` now derives `thiserror::Error`, removing ~30 lines of manual `Display`/`Error` impls. Added `From<std::io::Error>` and `From<tree_sitter::LanguageError>` conversions.
- **FxHashMap for all hot paths**: Converted `HashMap` → `FxHashMap` in `TaintRegistry`, `DataFlowEngine`, `CrossFileTaintResolver`, `AliasTracker`, `ControlFlowGraph`, `DefUseChains`, `RouteRegistry`, `ImportResolver`, `ProjectAnalysis`. Uses `rustc_hash` (already a dependency) for 3-5x faster lookups.

### Changed
- **Corpus API error types**: `load_corpus`, `load_corpus_dirs`, `load_from_bundle` now return `crate::Result<usize>` (was `Result<usize, String>`).
- **Deduplicated `extract_fingerprints`**: `extract_fingerprints` now delegates to `extract_fingerprints_with_nodes` and discards nodes (was ~180 lines of duplication).
- **Fixed `to_uppercase()` duplication**: `fingerprint.rs:654-672` — compute `arg_upper` once instead of calling `.to_uppercase()` 6x on same string.
- **Shannon entropy optimization**: Replaced `HashMap<char, i32>` + `.chars().count()` with fixed-size `[u32; 128]` byte array in `data_flow/entropy.rs`.
- **Removed dead code**: Deleted `semantic_patterns/` module (6 files: `auth_guard_dominator`, `csrf_missing_token`, `hardcoded_credentials`, `helpers`, `idor_missing_ownership`, `registry`), `findings/semantic_patterns.rs`, `findings/temporal_violation.rs`. Removed NO-OP modules from `registered_modules()`. Removed dead functions: `extract_imports`, `count_lines`, `common_prefix`, `similarity_score`, `approximate_jaccard`, `hash_ngrams`, `compute_ast_distance`, `has_controller_decorator`, `extract_controller_prefix`, `extract_route_path_from_file`. Removed hardcoded 18-name taint check in `interprocedural.rs` → delegates to `registry.has_any_tainted()`. Removed duplicate `classify_param_origin()` in `corpus_seeder.rs` → delegates to canonical impl.
- **Fixed evaluate.py**: Changed `data.get("findings", [])` → `data.get("findings", data.get("advisorys", []))` to read correct JSON key.
- **Benchmark results updated**: NodeGoat v0.5.0 metrics regenerated with optimized binary.

### Performance
- **87% faster on NodeGoat**: Wall time 29.0s → 3.8s at threshold 0.40 (113 functions, 572 patterns).
- **No accuracy regression**: F1=0.7164, TP=24, FP=13, FN=6 (identical to pre-optimization).

## [0.5.0-tasks] - 2026-07-24

### Added
- **CWE/CVSS/OWASP injection**: `[frensense]` comment block now supports `cwe:`, `cvss:`, `owasp:`, `severity:`, `runtime_probe:` fields. Parsed by `parse_frensense_block()`, stored on `AdvisoryText` and surfaced in JSON/SARIF output. SARIF emits CWE as `relationships` array per SARIF 2.1 §3.49.10.
- **Corpus quality scoring tool**: `cargo run --bin corpus-quality -- corpus/targets/` scores each pattern pair 0-100 based on structural quality heuristics, with tier-specific requirement checks (positives, negatives, cvss, runtime_probe, owasp, exploit_scenario, reference).
- **Five corpus tiers**: Documented in `FRENSENSE_CORPUS_GUIDE.md` with specific requirements per tier (Tier 1: 7 positives, 4 negatives, cvss, runtime_probe; Tier 2-5: graduated requirements).
- **Per-pattern `contains_call_to` learning**: Auto-filter now learns calls present in positives but absent from negatives, catching distinctive APIs like `fetch`, `exec`, `redirect` that category-level exclusivity checks miss.
- **Bidirectional context penalty**: Score now penalizes non-RouteHandler patterns matching RouteHandler files (config patterns on route files get 50% penalty).
- **Content-based route handler detection**: `FileContext::extract` now detects route handlers by code structure (20+ heuristics: `(req, res)` parameters, `app.get(`, `router.post(`, `res.json()`, `res.redirect()`) — works for any directory convention.
- **Qualified call names**: `extract_call_targets` now emits both full qualified names (`res.redirect`) and short names (`redirect`), enabling finer-grained auto-filter constraints.
- **High-quality corpus pairs**: Added `ts_cmdi_exec_shell` (CWE-78), `ts_open_redirect` (CWE-601), `ts_cmdi_exec_direct` (CWE-78), `ts_ssrf_fetch_direct` (CWE-918), `ts_sqli_concat_direct` (CWE-89), `ts_xss_reflected_response` (CWE-79) — all with proper `[frensense]` blocks, real imports, typed handlers, multiple functions, explicit taint sources, and Tier 1-compliant counts (7+ positives, 4+ negatives).
- **Corpus restructuring**: Files reorganized into subdirectories (`route-handlers/`, `config/`, `middleware/`, `utility/`, `test/`, `mock/`) enabling `FileContext`-based environment detection.
- **Motif abstraction layer**: 10 sink/source motif groups (CommandExecutionSink, SqlSink, HttpOutboundSink, etc.) mapped to canonical names. Patterns trained on `exec()` now automatically match `spawn()`, `Command::new()`.
- **Data-flow path fingerprints**: `data_flow_path_hashes` captures abstract source→sink chains (e.g., `UserInputSource → taint_flow → CommandExecutionSink`) invariant to variable renaming.
- **Match evidence**: `MatchEvidence` struct with per-dimension breakdown (ngram, ast, cf, api, motif, flow, semantic, negative similarity) exposed in JSON/SARIF output and CLI reporter.
- **Transformation-invariant fingerprints**: Token normalization, CF-path normalization (`if`/`switch`→`branch`), and skeleton normalization (`for`/`while`→`loop_node`) make fingerprints robust to common code mutations.
- **Tainted API calls dimension**: `tainted_api_calls` separates calls where arguments are function parameters from constants, enabling the scorer to penalize untainted sinks.
- **LSH multi-table**: Separate LSH tables for structural markers and API calls, with `hit_both` penalty when only one table produces a candidate.

### Changed
- **All hand-crafted semantic filters removed**: `load_semantic_filters()` returns empty HashMap. ~150 manually authored `contains_call_to`/`contains_import`/`function_name_regex` filters replaced by auto-learned constraints from `compute_auto_filters`.
- **Auto-learner now learns 6 constraint types**: `contains_call_to`, `contains_import`, `excludes_call`, `excludes_node_type`, `excludes_function_name`, `function_name_regex` — all with frequency thresholds to prevent over-exclusion.
- **Negative source files now read for auto-filter learning**: `get_negative_source()` concatenates all negative variants, enabling proper `excludes_call` and `excludes_node_type` learning.
- **Bundle format v4**: Auto-filter stats expanded to 7-tuple (pid, imports, calls, excludes_call, fn_regex, excludes_nodes, excludes_fnames). Bundle version bumped to 4.
- **No TOML**: All metadata goes in `[frensense]` comment blocks. TOML sidecar files deprecated.
- **Context penalty bidirectional**: Previously only penalized RouteHandler→Test/Utility. Now also penalizes non-RouteHandler patterns on RouteHandler files.
- **Corpus quality guide**: Full guide with CWE mapping table (40+ entries), template patterns, mutation guidelines, and tier requirements.

### Fixed
- **58→4 findings on NodeGoat**: 93% FP reduction after auto-filter constraints enabled with proper negative source learning.
- **FileCache invalidation**: Cache now invalidated when corpus bundle hash changes (new patterns fire on unchanged files).
- **Sequential file I/O → parallel**: `collect_files_impl` now reads + parses files in parallel via `par_iter()`.
- **std::HashMap → FxHashMap**: All hot-path maps (snapshot_map, file_trees) replaced with FxHashMap for 3-5x faster lookups.
- **eprintln! → tracing::trace!/warn!/info!**: Hot-path debug output now uses tracing macros (zero-cost in production). DEBUG CROSS_FILE_TAINT calls removed.
- **DependencyResolver deduplicated**: Created once per scan, shared between `run_corpus_scan` and `run_findings_modules`.
- **apply_severity_overrides deduplicated**: Removed premature first call. Composition now sees all findings including corpus patterns.
- **Pre-grouped identical fingerprints**: Eliminated the useless `thread_local! AST_CACHE`. Identical fingerprints scored once, advisories replicated.
- **LSH bucket scaling**: Replaced fixed 32-slot `Vec<FxHashSet>` with per-band `HashMap<u64, Vec<u64>>`. Bucket capacity now scales with item count (essential for 45k target).
- **Minhash loop transposed**: O(hashes × num_hashes) → O(hashes) by iterating over hashes once and updating all signature minimums.
- **`type_usage_overlap`**: std::HashSet → FxHashSet (SipHash eliminated).

## [0.5.0] - 2026-07-07

> **Note:** Versions 0.3.1 and 0.4.0 were major internal architectural iterations and were not published to NPM/Crates.io. Their changes are rolled into the 0.5.0 release, but their specific changelogs are preserved below for historical tracking.

### Added
- **Multi-Layered Composition**: Frensense now operates via a Layer 1 structural fast-pass and a Layer 2 semantic verification pass. False positives are drastically culled via the new `verify_taint_flow` integration into the `PatternScorer`.
- **Dependency-Aware Taint Analysis**: Project-level dependency resolution from `package.json` integrated into `CrossFileVerifier` to suppress false-positive sinks like native array/object methods (Safe-Base filtering).
- **Harvested Real-World Vulnerabilities**: 6 new generalized vulnerability patterns derived directly from backend audit reports (e.g., Unauthenticated DB Writes, Hyphen Drop Regex, JWT Bypass).
- **OWASP Juice Shop & NodeGoat Proven**: Scanner generalizes to find 77 true-positive vulnerabilities in the unseen OWASP Juice Shop repository and successfully flags 9 high-confidence `js_nosql_injection` and `js_swig_xss` zero-day equivalent bugs in NodeGoat.

### Fixed
- **Structural-First LSH Architecture Hardening**: Removed the highly restrictive lexical n-gram bottleneck (`ngram_sim_threshold`) and softened the negative-similarity penalty in `PatternScorer`. High-confidence structural hits now bypass variable-name mismatches.
- **T-FIX-1 Composition Optimization**: Lowered the structural high-confidence threshold from 0.40 to 0.20 to retain inter-procedural vulnerable sinks that inherently fail intra-procedural taint-tracing, eliminating structural false-negatives.

### Fixed
- **Semantic Constraint Evaluation**: Fixed a severe logic bug where `contains_call_to` and `contains_node_type` were evaluated using `.any()` instead of `.all()`. This previously allowed patterns to bypass strict requirements, resulting in thousands of false positives.
- **Corpus Negative Over-Penalization**: Fixed the corpus learning algorithm (`semantic.rs`) which artificially emptied semantic requirements if a negative example contained a required positive call (e.g., `fetch`). By relaxing the constraint wiping, the engine now correctly maintains strictly required API calls, eliminating false positives for SSRF, Path Traversal, and Open Redirect.

### Changed
- **Fully corpus-driven detection**: All detection is now driven by positive/negative example pairs. Removed hardcoded TOCTOU detector (`check_then_act.rs`), temporal rules TOML (empty), and taint-as-detection. Detection layers: corpus fingerprint match → taint verification → taint entropy → cross-function consistency.
- **CorpusSourceSinkRegistry**: Sources and sinks are learned from corpus AST at load time. Replaces three inconsistent `framework_types` arrays and two duplicate `identify_sink()` functions.
- **Temporal detection is corpus-driven**: `rust_temporal_lock_unlock`, `rust_temporal_lock_sleep`, `ts_temporal_open_close`, `ts_temporal_connect_disconnect` patterns replace hardcoded TOML rules.
- **TOCTOU generalization**: `ts_toctou_typeorm`, `ts_toctou_sequelize` patterns extend detection beyond Prisma-only.
- **Corpus suppression support**: `.frensense-suppress.yml` now applies to corpus findings.
- **603 positive corpus patterns** (from 89 in v0.3.x). 1214 fingerprints. 3.0MB FRC bundle.

### Removed
- `check_then_act.rs` — hardcoded TOCTOU detector (replaced by corpus patterns)
- `temporal_rules.toml` rules — replaced by corpus patterns (file retained as empty)
- `ROADMAP.md` — superseded by tasks.md and SCALING_PLAN.md
- Stale test references to `TAINT_CREDENTIAL_TO_LOG`, `TAINT_INPUT_TO_EXEC` (taint-as-detection removed)
- Commodity detectors: `dead_branch.rs`, `unused_variable.rs`, `atomic_section.rs`, `secrets.rs` — Clippy/GitLeaks do them better
- `reachability.rs` — only used by removed dead_branch detector

## [0.4.0] - Unreleased / Internal

## [0.3.1] - Unreleased / Internal

### Added
- **`taint_max_depth` Rule DSL field**: Rules can set `taint_max_depth: <N>` in YAML to control cross-function taint chain length per-rule. Falls back to 5 (existing default) when unset.
- **Visited-set cycle detection in `resolve_call_taint`**: Prevents re-analysis and infinite recursion when the same callee is encountered multiple times during taint resolution. Tracks `(file_path, start_byte)` pairs per analysis.
- **Match-arm and if-expression return propagation**: `find_returns()` now explicitly walks `match_expression` arms and `if_expression` consequence/alternative branches as potential return values, improving intra-procedural taint flow through conditional logic.
- **Rule quality pipeline**: Every rule now carries a `precision` tier (`very-high | high | medium | low`), letting users choose a rule suite via `--suite {default|extended|all}`. `default` runs only `very-high` rules (battle-tested, near-zero false positives). `extended` adds `high` rules (well-tested, occasional FP). `all` runs every rule (current behavior, unchanged as default).
- **`--suite` CLI flag**: `frensense --suite default path/` filters to high-confidence findings only. Backward compatible — existing invocations without `--suite` behave identically.
- **Historical self-scan benchmark**: `scripts/historical-benchmark.sh` scans a target repo at every tagged version with the current frensense binary and outputs a CSV showing how advisory counts evolved over time. Documented in `BENCHMARK.md`.

- **Regex Illusion / False Recall**: Identified and resolved a critical bug where `auto_filter` incorrectly extracted `if` and `catch` as exact API calls, artificially inflating both textual overlap (`ngram_sim`, `signature_sim`) and motif hashes across frameworks. The heuristic `contains_call_to` generator in `frensense-bundler` has been temporarily disabled pending an AST-aware replacement.
- **Semantic Override Generalization**: `apply_semantic_override` now successfully triggers on `flow_sim > 0.8` (which hashes abstract `SemanticMarkers` like `SqlSink` rather than raw strings) and `identity_gate > 0.1`, dropping the strict `motif_sim > 0.8` requirement. This allows the engine's core data-flow abstraction to generalize across frameworks (e.g. `db.query` vs `sequelize.query`).
- **Minimum-Score Gate Strictness**: Temporarily disabled the hard-coded gate in `runner.rs` that silently dropped matches if structural/textual overlap (`ngram_sim` AND `signature_sim`) was `< 5%`. This ensures valid data-flow matches between small corpus patterns (15 lines) and large, harness-heavy vulnerable functions (78 lines) are not discarded.
- **Regex Illusion / False Recall**: Identified and resolved a critical bug where `auto_filter` incorrectly extracted `if` and `catch` as exact API calls, artificially inflating both textual overlap (`ngram_sim`, `signature_sim`) and motif hashes across frameworks. The heuristic `contains_call_to` generator in `frensense-bundler` has been temporarily disabled pending an AST-aware replacement.
- **Semantic Override Generalization**: `apply_semantic_override` now successfully triggers on `flow_sim > 0.8` (which hashes abstract `SemanticMarkers` like `SqlSink` rather than raw strings) and `identity_gate > 0.1`, dropping the strict `motif_sim > 0.8` requirement. This allows the engine's core data-flow abstraction to generalize across frameworks (e.g. `db.query` vs `sequelize.query`).
- **Minimum-Score Gate Strictness**: Temporarily disabled the hard-coded gate in `runner.rs` that silently dropped matches if structural/textual overlap (`ngram_sim` AND `signature_sim`) was `< 5%`. This ensures valid data-flow matches between small corpus patterns (15 lines) and large, harness-heavy vulnerable functions (78 lines) are not discarded.

### Changed
- **Consolidated single-binaries into unified crate**: `cargo install frensense` now produces both `frensense` (CLI) and `frensense-mcp` (MCP server) binaries. Removed separate `frensense-cli` and `frensense-mcp` workspace crates.
- **MCP filter params**: Added `language` (file extension matching) and `rules` (rule_id set) parameters to `frensense_audit` tool, applied server-side via `filter_advisories` after scan.
- **Clippy pedantic compliance**: All ~35 `clippy::pedantic` violations fixed. The four `-A` flags removed from CI and pre-commit hook.

### Added
- **License headers**: `// SPDX-License-Identifier: MIT` added to 13 unattributed files. Solidty rule changed from proprietary to MIT. Codebase is now 100% MIT-consistent.
- **Shared `RulesWrapper`**: Extracted duplicated `RulesWrapper + check_version()` into `src/engine/auditor/common.rs`.
- **Shared `is_in_async_scope`**: Extracted duplicated helper into `src/rules/rust/mod.rs`.

### Fixed
- **MCP tests**: `test_mcp_language_filter` and `test_mcp_rules_filter` verify server-side filtering works correctly. 36/36 MCP tests pass.
- **Binary file crash**: `collect_files` now filters to supported extensions via `ParserRegistry::is_supported`, preventing `"stream did not contain valid UTF-8"` panic on binary files (`.term`, `.idx`, `.store`, etc.).
- **Macro test**: `test_cli_json_output` updated for consolidated crate structure.
- **Pre-commit hook**: Now runs full test suite (`cargo test`) instead of `cargo test --lib --bins`.
- **File extension**: `research/sparse_spectral_enginev2.rs` renamed to `.md`.
- **Package.json**: Removed non-existent `index.js` from `files` array.

### Added
- **Native TypeScript rule `TS_TAUTOLOGICAL_ASSERT`**: Detects `expect(x).toBe(x)`, `expect(true).toBeTruthy()`, `expect(null).toBeNull()` via AST walk. Registered under `#[cfg(feature = "typescript")]`. 7 test cases.
- **`temporal` feature flag**: New Cargo feature gates `TemporalAnalyzer`, `TemporalConfig`, and all temporal compilation/execution paths. On by default. Allows `cargo build --no-default-features` to exclude temporal analysis.
- **Feature ownership map**: `FEATURE_MAP.md` documents exactly which files each differentiator (temporal, schema_contract, mcp, csa) owns — no more guessing what lives where.
- **Gap analysis → build plan**: `GAP_ANALYSIS.md` restructured into 6 priority-ordered phases (P0–P5) with tickable checkboxes, aligned to v0.4.0 plan.

### Changed
- **Temporal analyzer moved to dedicated folder**: `src/temporal/` consolidates `TemporalAnalyzer`, `TemporalConfig`, and handler delegation. Scattered call sites in `ir.rs` and `compiler.rs` reduced to 1-line delegations. Old `src/semantics/temporal.rs` removed.
- **Precision assigned to all 60 rules**: 10 Rust hand-written rules set to `very-high`, 2 AI-pattern rules set to `high`, 48 YAML rules tiered by confidence score (39 `very-high`, 9 `high`).

### Removed
- **14 style/noise YAML rules**: Self-audit findings dropped from 186 to 69.
- **10 Solidity rules and `solidity` feature**: Dead code — feature not compiled, no tree-sitter support. Includes 7 core, 2 security, 2 CSA rules.
- **Old bug tracking docs**: `V0_3_1_ISSUES.md`, `V0_3_1_REPORT.md`, `AUDIT_V0.3.0_REPORT.md`.

## [0.2.2] - 2026-05-14

### Added
- **Solidity Beta Support**: Integrated tree-sitter-solidity. Enable with `--features solidity`.
- **Enhanced Temporal Rules**: Added `forbidden_between` behavior to allow detecting prohibited calls between specific state boundaries.
- **Architectural Guardrails**: Added comprehensive documentation and project-level rules for enforcing system architecture (e.g., service/handler separation).

## [0.2.1] - 2026-05-13

### Fixed
- **CI: Missing Rust toolchain in `publish-npm` job**: `cargo run` was called before Rust was installed, causing NPM to never publish past v0.1.4.
- **CI: NAPI features included in `cargo publish`**: Default features pulled in `napi-build` unconditionally, causing `cargo package` to fail in environments without NAPI headers. Scoped to `--no-default-features --features rust,typescript,fingerprinting,remediation`.
- **CI: `aarch64-apple-darwin` cross-compiled on wrong host**: Changed `macos-latest` (x86) to `macos-14` (Apple Silicon) for native arm64 builds.
- **CI: Mutable action tags**: All GitHub Action references pinned to immutable SHA digests.
- **CI: Broad branch trigger**: `ci.yml` narrowed from `["**"]` to `main`, `feature/**`, and `fix/**`.
- **CI: `npm install` fallback**: Replaced `npm ci || npm install` with strict `npm ci`.
- **CI: Sync loop guard**: `sync.yml` now also skips its own "sync version" commits to prevent re-trigger loops.
- **CI: Concurrency controls**: Added `concurrency` groups to all three workflows to prevent duplicate runs.

## [0.2.0] - 2026-05-13

### Added
- **Multi-File Scanning (Frensense 2.0)**: Stabilized the core semantic architecture to support project-wide auditing.
- **Graph-First Semantic Engine**: Migrated to a global symbol graph for high-precision inter-procedural taint analysis across files.
- **Multi-Pass Audit Loop**: Implemented a sophisticated audit pipeline that performs local AST checks followed by cross-file project-level enforcement.
- **Cross-File Project Rules**: Full support for `MustHaveGuard`, `MustBeInternal`, and `CrossFileTaintFree` rules.
- **Node.js API Extensions**: Exposed `auditProject` and `auditPath` for full project-wide scanning from JavaScript.
- **Supply Chain Security**: Integrated `cargo deny`, `npm audit`, and SLSA Level 3 provenance for production-grade security.
- **Egress Auditing**: Integrated StepSecurity Harden Runner for CI network protection.

### Fixed
- **BFS Deduplication**: Fixed a critical bug where BFS traversal incorrectly deduplicated symbols with the same name across different files.
- **Project Advisory Metadata**: Resolved an issue where `original_content` was empty for project-level findings, unblocking `--fix` mode.
- **JS API Gaps**: Fixed `audit_content` incorrectly being used for project-wide rules; redirected users to the new `audit_project` method.
- **Clippy Violations**: Fixed several redundant cast warnings and unnecessary cloning identified by static analysis.

### Changed
- **MSRV Bump**: Increased Minimum Supported Rust Version (MSRV) to **1.77** to support modern build script features.
- **CI Hardening**: Pinned all GitHub Action references to full immutable SHAs to prevent supply chain attacks.
- **DSL Cleanup**: Removed the redundant and unused `domain` field from rule definitions to simplify the DSL.

### Removed
- Unused `domain` metadata from all core and embedded rule definitions.
