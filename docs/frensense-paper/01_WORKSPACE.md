# Workspace Structure

This document maps every directory and file in the Frensense workspace.

---

## Cargo Workspace Members

```toml
[workspace]
members = [
    "frensense-bundler",
    "frensense-engine",
    "frensense-frc",
    "frensense-lang",
    "frensense-providers",
    "frensense-runtime",
]
resolver = "2"
```

The root `Cargo.toml` also defines the primary `frensense` package (CLI + lib), making the repo a 7-crate workspace.

---

## Dependency Graph

```
frensense (CLI/lib)
 ├── frensense-engine   (core analysis, no CLI)
 │    ├── frensense-lang
 │    └── frensense-frc
 ├── frensense-bundler  (corpus compiler)
 │    ├── frensense-engine
 │    └── frensense-frc
 └── frensense-providers (optional compiler backends)
      └── frensense-engine

frensense-runtime      (standalone sidecar, no engine dep)
frensense-frc          (no internal deps — format-only leaf crate)
frensense-lang         (no internal deps — spec-only leaf crate)
```

---

## Full Annotated File Tree

```
Frensense/
│
├── Cargo.toml                  Root workspace + frensense package manifest
├── Cargo.lock                  Reproducible dependency lockfile
├── deny.toml                   cargo-deny: license and vulnerability policy
├── Makefile                    Build automation (bench, bundle, test targets)
├── Dockerfile                  Docker image for CI and deployment
├── .env                        Dev environment variables (not committed to prod)
├── .gitattributes              Git LFS + diff driver config
├── .gitignore
├── .semgrepignore              Semgrep exclusions (vendored code, generated files)
│
├── README.md                   User-facing quick-start guide
├── CHANGELOG.md                Version history
├── FRENSENSE_CORPUS_GUIDE.md   Corpus authoring quality guide (5 tiers, CWE table)
│
├── frensense-corpus.frc        Pre-compiled corpus bundle (17 MB, binary)
├── per_category_calibration.json  Per-category sigmoid calibration parameters
│
├── src/                        Root crate source
│   ├── lib.rs                  Public API: Advisory, FrensenseRule, TaintCache, FrensenseContext
│   ├── parser.rs               File extension → language string mapping
│   ├── reporter.rs             Output formatters: terminal ANSI, JSON, SARIF
│   │
│   ├── bin/
│   │   ├── frensense.rs        Main CLI entry point
│   │   ├── frensense-mcp.rs    MCP JSON-RPC server binary
│   │   └── corpus-quality.rs   Corpus pattern quality scoring utility
│   │
│   ├── cli/                    CLI argument definition and dispatch
│   │   ├── mod.rs
│   │   ├── commands.rs         Subcommand handlers (scan, learn, build-bundle)
│   │   ├── extras.rs           Extra CLI utilities
│   │   ├── options.rs          Full argument schema (clap-derived, ~29KB)
│   │   └── reporting.rs        Finding output formatting from CLI options
│   │
│   ├── engine/                 Scan orchestration layer
│   │   ├── mod.rs
│   │   ├── auditor/            FrensenseAuditor: top-level file walker + rule dispatcher
│   │   ├── ast_diff.rs         AST-level diff for pattern extraction from pairs
│   │   ├── clustering.rs       Near-duplicate function detection
│   │   ├── composition.rs      Multi-layer AND-gate confidence composition
│   │   ├── confidence_calibration.rs  Per-finding calibration application
│   │   ├── findings/           Finding deduplication, suppression, baseline logic
│   │   ├── learn.rs            Pattern learning from positive/negative pairs
│   │   ├── negative_miner.rs   Mine negatives from existing codebase functions
│   │   ├── per_category_calibration.rs  Load per-category sigmoid params
│   │   ├── project/            Project-level analysis (cross-file aggregation)
│   │   └── source.rs           SourceRegistry: file source loader
│   │
│   ├── mcp/                    Model Context Protocol server
│   │   ├── mod.rs
│   │   ├── audit.rs            MCP-exposed scan endpoint
│   │   ├── handler.rs          JSON-RPC request handler
│   │   └── protocol.rs         MCP protocol types and serialization
│   │
│   ├── patcher/                Auto-fix code patcher
│   │
│   ├── semantics/              Semantic rule implementations
│   │   ├── mod.rs
│   │   ├── consistency.rs      Cross-function consistency checker
│   │   ├── data_flow/          Interprocedural taint walking rules
│   │   ├── provider.rs         SemanticProvider wiring
│   │   └── simple_taint.rs     Intraprocedural single-file taint rule
│   │
│   └── temporal/               Temporal property checker
│       ├── mod.rs
│       ├── analyzer.rs         LTL sequence property checker
│       └── config.rs           Built-in temporal rules (financial, auth lifecycle)
│
├── frensense-engine/           Core analysis library crate
│   └── src/
│       ├── lib.rs              analyze_file(), analyze_project(), public API types
│       ├── ast_distance.rs     Tree edit distance (skeleton comparison)
│       ├── auto_filter.rs      AutoFilterStats: corpus-derived filter statistics
│       ├── decorator.rs        HTTP decorator classifier (@Get, @Post, @Controller)
│       ├── deps.rs             Dependency advisory rules (npm/cargo known vulns)
│       ├── export_matcher.rs   Export pattern matching (CJS module.exports, ESM)
│       ├── function_role.rs    FunctionRole classifier (HttpHandler, DbQuery, etc.)
│       ├── graph.rs            SemanticGraph: call graph using petgraph DiGraph
│       ├── import_resolver.rs  ImportMap: import alias → package resolution
│       ├── minhash.rs          MinHash signature + banded LSH index
│       ├── parser.rs           ParserRegistry: tree-sitter grammar loading
│       ├── per_pattern_calibration.rs  Per-pattern sigmoid (A, B) loader
│       ├── profile.rs          ProjectProfile: codebase n-gram frequency distribution
│       ├── route_registry.rs   HandlerRegistry: route registration tracking
│       ├── semantic.rs         SemanticProvider trait + ImportMapProvider impl
│       ├── symbols.rs          SymbolRegistry: function/class symbol table
│       │
│       ├── cfg/                Control Flow Graph builder
│       │   ├── mod.rs          ControlFlowGraph, BasicBlock, CFEdgeKind
│       │   └── def_use.rs      Reaching definitions, def-use chains (DefState)
│       │
│       ├── context/            File context classifier
│       │   └── mod.rs          FileContext: RouteHandler, Library, Test, Script, etc.
│       │
│       ├── corpus/             Corpus pattern matching core
│       │   ├── mod.rs
│       │   ├── bundle.rs       BundlePattern, BundlePayload deserialization
│       │   ├── data_flow_extractor.rs  Taint path extraction from corpus pattern source
│       │   ├── flow_fingerprint.rs     Intra-function flow path hashing (FlowPath)
│       │   ├── motifs.rs       Source/sink semantic motif definitions (MOTIFS table)
│       │   ├── pattern.rs      CorpusPattern struct
│       │   ├── registry.rs     PatternRegistry: LSH index, scoring, matching orchestration
│       │   ├── semantic.rs     SemanticFilter: pre-match AST constraint gate
│       │   └── source_sink.rs  CorpusSourceSinkRegistry: per-corpus sink definitions
│       │
│       ├── data_flow/          Taint analysis subsystem
│       │   ├── mod.rs          TaintOrigin enum, TaintRegistry (scope stack), param classifiers
│       │   ├── alias.rs        AliasTracker: pointer/reference alias propagation
│       │   ├── confidence.rs   Taint confidence scoring model
│       │   ├── cross_file.rs   Interprocedural taint resolver (BFS over call graph)
│       │   ├── engine.rs       DataFlowEngine: per-function taint AST walker
│       │   ├── entropy.rs      Shannon entropy calculator for secret detection
│       │   ├── normalization.rs  SemanticOp: normalized taint IR (Binding, Assignment, Call)
│       │   ├── pii.rs          PII taint source classifier
│       │   ├── propagators.rs  PropagatorRegistry: language-specific propagation rules
│       │   ├── reaching_defs.rs  Reaching definition dataflow analysis
│       │   ├── resolver.rs     Function definition resolution (resolve_fn_definition)
│       │   ├── sanitizer.rs    SanitizerRegistry: known sanitizer functions
│       │   └── taint_metrics.rs  TaintMetrics: branch-ratio, validation name detection
│       │
│       ├── fingerprint/        Function fingerprint extraction
│       │   ├── mod.rs          Public API: extract_fingerprints(), IDF weight functions
│       │   ├── ast_walkers.rs  All AST traversal functions (28KB — the core walker)
│       │   ├── extraction.rs   extract_fingerprints_with_nodes() entry point
│       │   ├── hashing.rs      Token normalization, rolling ngram hash, positional ngrams
│       │   └── types.rs        FunctionFingerprint struct (27 fields), compute_idf_weights()
│       │
│       ├── lang/               Language-specific AST node mapping
│       │   ├── mod.rs          Language enum, spec_for_ext() dispatch
│       │   ├── kinds.rs        Node kind string constants
│       │   └── mapper.rs       Tree-sitter node kind → NodeRole mapping per language
│       │
│       └── pattern/            Pattern matching and scoring
│           ├── mod.rs
│           ├── canonical.rs    CanonicalForm: normalized fingerprint for cross-language compare
│           ├── compiler.rs     PatternNode: compiled pattern internal representation
│           ├── evidence.rs     MatchEvidence: per-dimension score breakdown (SARIF-friendly)
│           ├── matcher.rs      MatchResult, candidate selection from LSH output
│           ├── scorer.rs       PatternScorer: 15-dimensional weighted scoring (27KB)
│           ├── similarity.rs   RawDimensions: individual similarity metric computation
│           └── weight_learner.rs  DEFAULT_WEIGHTS and per-category weight learning
│
├── frensense-bundler/          Corpus compiler crate
│   └── src/
│       ├── lib.rs
│       ├── main.rs             Bundler binary entry point
│       ├── auto_filter.rs      Auto-derive SemanticFilter constraints from corpus pairs
│       ├── builder.rs          build_bundle_from_patterns(): orchestration + FRC serialization
│       ├── calibration.rs      Per-pattern sigmoid calibration fitting
│       ├── loader/             Corpus directory scanner and parser
│       └── pattern/
│           └── weight_learner.rs  learn_category_weights() optimizer
│
├── frensense-frc/              Binary bundle format crate
│   └── src/lib.rs              BundleHeader, write_bundle(), read_bundle(), BLAKE3 checksum
│
├── frensense-lang/             Language specification crate
│   └── src/
│       ├── lib.rs              TaintOrigin, spec_for_ext() factory
│       ├── registry.rs         LanguageRegistry
│       ├── spec.rs             LanguageSpec trait, NodeRole enum (full grammar abstraction)
│       └── providers/          Per-language implementations
│           ├── typescript.rs   TypeScript/JavaScript spec
│           ├── rust.rs         Rust spec
│           ├── go.rs           Go spec
│           └── python.rs       Python spec
│
├── frensense-providers/        Optional compiler backends crate
│   └── src/
│       ├── lib.rs
│       ├── oxc_provider.rs     OxcProvider: exact JS/TS resolution via Oxc (37KB)
│       └── rust_hir_provider.rs  RustHirProvider: Rust HIR via rust-analyzer (23KB)
│
├── frensense-runtime/          Dynamic runtime instrumentation crate
│   └── src/
│       ├── lib.rs
│       ├── main.rs             Runtime sidecar process entry point
│       ├── advisory.rs         Runtime finding formatter
│       ├── canary.rs           Canary payload injection
│       ├── config.rs           Runtime configuration
│       ├── oracle.rs           Ground-truth oracle query
│       ├── route_extractor.rs  HTTP route extraction from running process
│       ├── scheduler.rs        Probe scheduling engine
│       ├── session.rs          Session lifecycle management
│       ├── tracer.rs           Execution trace collection
│       ├── adapters/           Language runtime adapters (Node, Rust, Go)
│       └── probes/             Individual probe definitions
│
├── corpus/
│   └── targets/                Corpus source files
│       ├── ts_sqli_*.ts        TypeScript SQL injection patterns
│       ├── ts_ssrf_*.ts        TypeScript SSRF patterns
│       ├── ts_cmdi_*.ts        TypeScript command injection patterns
│       ├── rs_*.rs             Rust patterns
│       └── ...                 200+ pattern pairs
│
├── docs/                       Documentation
│   ├── ARCHITECTURE.md         Original architecture overview
│   ├── AUTO_FILTER.md          Auto-filter design
│   ├── SCORING_DIMENSIONS.md   11→15 dimension scoring model
│   ├── MATCH_EVIDENCE.md       Per-dimension evidence breakdown
│   ├── TECHNICAL_REFERENCE.md  Deep technical reference (~41KB)
│   ├── LIMITATIONS_MAP.md      Known limitations (~49KB)
│   └── frensense-paper/        ← You are here
│
├── tests/                      Integration tests
│   └── benchmarks/engine_perf.rs  Criterion benchmark
│
└── scripts/                    Utility scripts
```

---

## Excluded Paths

The engine automatically skips these during scanning (enforced in `auditor/`):

| Pattern | Reason |
|---|---|
| `node_modules/`, `target/`, `dist/`, `build/`, `vendor/`, `out/` | Build artifacts |
| `.*` (hidden directories) | Configuration, tooling |
| `*.test.*`, `*.spec.*`, `__tests__/`, `mocks/` | Test files |
| `*.min.js`, `*.bundle.js`, `*.chunk.js` | Generated/minified bundles |
| Files `> 1 MB` | Performance |
