# Frensense — System Overview

**Version:** 0.5.x  
**Authors:** Friehub Developers  
**License:** MIT

---

## Abstract

Frensense is a high-performance static analysis system for Rust, TypeScript, and JavaScript that detects security vulnerabilities, architectural violations, and AI-generated code hallucinations — without hand-written rules, DSLs, or regular expressions.

The core thesis: **code patterns are best expressed as pairs of concrete examples** — a vulnerable function and its corrected counterpart. These pairs carry richer signal than any YAML rule because they encode structural shape, control flow, API usage, and data flow simultaneously. The engine fingerprints corpus pairs at build time and performs fast, multi-dimensional similarity search at scan time.

Findings fire only when multiple independent layers agree: structural corpus match, taint data-flow confirmation, and (optionally) cross-function consistency. This AND-gate architecture is what drives the system's low false-positive rate.

---

## Problem Statement

Existing static analysis tools fall into two paradigms:

| Paradigm | Examples | Weakness |
|---|---|---|
| **Rule-based** | Semgrep, ESLint, Clippy | Brittle to syntactic variation; every new bug class needs a hand-written rule |
| **ML-based embedding** | CodeBERT fine-tunes, DeepBugs | Opaque predictions; high FP rate in production; expensive inference |

Frensense occupies a middle ground: the detection patterns are *data* (real code examples) rather than *rules* (DSL expressions), but the matching is *deterministic* and *explainable* (every finding comes with a per-dimension score breakdown).

---

## What It Catches

Three distinct categories are encoded in the corpus:

1. **Security Vulnerabilities**
   - SQL/NoSQL injection (CWE-89, CWE-943)
   - Server-Side Request Forgery (CWE-918)
   - Path Traversal (CWE-22)
   - Command Injection (CWE-78)
   - Credentials flowing to logs or HTTP responses

2. **Architectural Invariants**
   - `validate_*()` functions with no rejection path (hollow validators)
   - Missing payment gates before wallet operations
   - Ownership checks missing from update/delete endpoints

3. **LLM Hallucinations in AI-generated Code**
   - Hardcoded tokens/secrets
   - AI-generated `any` parameters in TypeScript
   - `console.log` in production paths
   - `await` in synchronous contexts

---

## Design Principles

### 1. Zero Rule Authoring
All detection derives from the `.frc` corpus bundle. Adding a new pattern means dropping two files (`*_positive.ts`, `*_negative.ts`) and running `--build-bundle`. No TOML, no YAML, no DSL.

### 2. Multi-Layer Corroboration
A finding is emitted only when:
- **L1 (Corpus Match):** The function's structure mathematically resembles a known vulnerable pattern.
- **L2 (Taint Path):** Tainted data demonstrably flows from a source to the implicated sink.
- **L3 (Consistency):** Sibling functions do not contradict the pattern (no double-suppression).

### 3. Deterministic Output
Given the same source, corpus, and thresholds, the engine produces identical output on every run. No stochastic components in production paths.

### 4. Sub-Second Scan Times
- `rayon` parallelism across files and functions
- MinHash LSH pre-filtering reduces corpus matching to O(1) amortized per function
- Function-level granularity avoids re-analyzing unchanged code

### 5. Extensible Without Recompilation
New patterns compile into the `.frc` bundle. The scanner loads the bundle at startup — no code changes needed to extend detection coverage.

---

## Document Index

| File | What It Covers |
|---|---|
| [`00_OVERVIEW.md`](./00_OVERVIEW.md) | This file — abstract, goals, design principles |
| [`01_WORKSPACE.md`](./01_WORKSPACE.md) | Full annotated workspace and file tree |
| [`02_CRATE_FRC.md`](./02_CRATE_FRC.md) | `frensense-frc` — binary bundle format |
| [`03_CRATE_LANG.md`](./03_CRATE_LANG.md) | `frensense-lang` — language abstraction layer |
| [`04_CRATE_ENGINE.md`](./04_CRATE_ENGINE.md) | `frensense-engine` — core analysis library |
| [`05_CRATE_BUNDLER.md`](./05_CRATE_BUNDLER.md) | `frensense-bundler` — corpus compiler |
| [`06_CRATE_PROVIDERS.md`](./06_CRATE_PROVIDERS.md) | `frensense-providers` — compiler backends |
| [`07_CRATE_RUNTIME.md`](./07_CRATE_RUNTIME.md) | `frensense-runtime` — dynamic instrumentation |
| [`08_CRATE_ROOT.md`](./08_CRATE_ROOT.md) | Root crate — CLI, orchestration, MCP server |
| [`09_PIPELINE.md`](./09_PIPELINE.md) | End-to-end analysis pipeline |
| [`10_THEORY_MAP.md`](./10_THEORY_MAP.md) | CS theory mapped to every module |
| [`11_DATA_STRUCTURES.md`](./11_DATA_STRUCTURES.md) | Key data structures annotated |
| [`12_LIMITATIONS.md`](./12_LIMITATIONS.md) | Known issues and open problems |
| [`13_BENCHMARKS.md`](./13_BENCHMARKS.md) | Benchmark results |
| [`14_REFERENCES.md`](./14_REFERENCES.md) | Citations and bibliography |
