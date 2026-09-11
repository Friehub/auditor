# Benchmark Results

All benchmarks were run against publicly available vulnerable applications. Numbers reflect v0.5.3 unless otherwise noted.

---

## OWASP Juice Shop (September 2026)

**Target:** OWASP Juice Shop — the canonical web application security training benchmark.  
**Language:** TypeScript + Node.js  
**Vulnerable files:** 37 (CWE-89, CWE-918, CWE-22, CWE-78, CWE-79)  
**Corpus version:** frensense-corpus.frc v0.5.3 (17 MB)

### v0.5.3 vs v0.5.1 Comparison

| Metric | v0.5.1 | v0.5.3 | Delta |
|---|---|---|---|
| Total findings | 81 | 32 | -49 (-60%) |
| True Positives | 21 | 11 | -10 |
| False Positives | 60 | **21** | **-39 (-65%)** |
| **Precision** | 25.93% | **34.38%** | **+8.45 pp** |
| File Recall | 35.14% | 24.32% | -10.82 pp |

### Analysis

The large drop in findings from v0.5.1 to v0.5.3 reflects intentional changes:

1. **Raised LSH threshold** from 0.65 to 0.71 (fewer candidates reach scoring).
2. **Added identity gate** (multiplicative gate on max of identity-bearing dimensions).
3. **Taint penalty** (structural-only matches down-weighted 40%).
4. **Validator suppression refinement** (threshold raised from 0.60 to 0.85).

The precision improvement (+8.45 pp) comes at the cost of recall (-10.82 pp). This is the standard precision-recall tradeoff — the current tuning favors precision over recall, appropriate for a developer-facing tool where false positives are more disruptive than false negatives.

### Missing True Positives in v0.5.3

The 10 TPs lost vs. v0.5.1 are mostly:
- Functions where taint verification failed (cross-file taint at 3+ hops — see [`12_LIMITATIONS.md#L3`](./12_LIMITATIONS.md)).
- Functions with low n-gram overlap but high semantic similarity (the raised LSH threshold cut these from the candidate set).

---

## NodeGoat (v0.5.3)

**Target:** OWASP NodeGoat — MongoDB/Express vulnerable application.  
**Language:** JavaScript (CommonJS)  
**Known vulnerabilities:** 30 (across 14 files)

| Metric | Value |
|---|---|
| True Positives | 23 |
| False Positives | 33 |
| Precision | 41.07% |
| Recall | 56.67% (23/30 known vulnerabilities found) |

### NodeGoat vs Juice Shop Precision Gap

NodeGoat achieves 41% precision vs. Juice Shop's 34%. Reasons:
1. NodeGoat uses MongoDB — the corpus has more MongoDB-specific patterns (NoSQL injection, unvalidated MongoDB operators).
2. NodeGoat's vulnerable functions are less structurally similar to common safe functions — the identity gate is more effective.
3. NodeGoat's codebase is smaller (~5000 LOC vs. ~35000 LOC for Juice Shop) — fewer innocent functions that could be false-matched.

---

## Performance Benchmarks

Measured on an 8-core AMD Ryzen 7 (2.6 GHz), 32 GB RAM, NVMe SSD.

### Corpus Load Time

| Bundle Size | Patterns | Load Time |
|---|---|---|
| 17 MB (.frc v0.5.3) | 312 patterns | 180ms |

Load time includes BLAKE3 verification and LSH index construction.

### Scan Times (with corpus enabled)

| Codebase | Files | Functions | Wall Time |
|---|---|---|---|
| Small (2k LOC, 15 files) | 15 | ~90 | <200ms |
| Medium (10k LOC, 80 files) | 80 | ~500 | <1s |
| Large (100k LOC, 800 files) | 800 | ~5000 | ~4s |
| Juice Shop (35k LOC) | ~240 | ~1800 | ~2.5s |

### Per-Function Breakdown (medium codebase)

| Phase | Time per function |
|---|---|
| LSH candidate retrieval | ~0.01ms |
| Semantic filter check (all patterns) | ~0.1ms |
| 15-D scoring (per candidate, avg 8 candidates) | ~0.8ms |
| Taint verification (when triggered) | ~2-5ms |
| Total per function | ~1-6ms |

The dominant cost is taint verification. Taint is triggered only for functions that score above threshold — typically 5-15% of all functions in a codebase.

---

## Precision vs. Recall Tradeoff Analysis

The following shows how precision and recall change as the minimum confidence threshold is adjusted:

| Min Confidence | Findings | TP | FP | Precision | Recall |
|---|---|---|---|---|---|
| 0.50 | 51 | 14 | 37 | 27.5% | 37.8% |
| 0.60 | 38 | 12 | 26 | 31.6% | 32.4% |
| **0.65 (default)** | **32** | **11** | **21** | **34.4%** | **29.7%** |
| 0.75 | 21 | 9 | 12 | 42.9% | 24.3% |
| 0.85 | 11 | 7 | 4 | 63.6% | 18.9% |
| 0.90 | 6 | 5 | 1 | 83.3% | 13.5% |

**Takeaway:** At 0.90 confidence, precision reaches 83% but recall drops to 13.5%. For security scanning where coverage matters, the default 0.65 threshold strikes a balance. For automated CI gates where false positives are unacceptable, 0.85+ may be appropriate.

---

## Comparison with Semgrep (same target, same rules)

Semgrep was run against Juice Shop with the official Semgrep security rules repository.

## Honest Interpretation of the Semgrep Comparison

**Frensense is not competitive with Semgrep on this benchmark.** Semgrep is strictly better on both metrics simultaneously: higher precision (38.3% vs. 34.4%) and significantly higher recall (48.6% vs. 29.7%). Frensense emits fewer total findings — which is not an advantage, it means it both makes fewer correct calls and misses more real bugs.

### Why the gap exists

**1. Corpus size vs. rule count**

Frensense v0.5.3 ships 312 corpus pattern pairs. Semgrep's security rules repository contains ~3,000+ hand-authored rules. A corpus-driven approach cannot outperform a rule-based system in coverage unless the corpus is comparable in scope. 312 general patterns cannot cover the semantic diversity of real-world frameworks.

**2. Generalization is not free**

The corpus-driven thesis — "learn from examples, generalize to unseen code" — assumes the training distribution covers the structural patterns present in the target codebase. Juice Shop uses specific Express.js route shapes, specific Mongoose query constructions, and specific auth bypass idioms that the general corpus never saw. Semgrep's rules are written *against* those specific frameworks and match exactly.

**3. Contrastive scoring degrades when the target differs from both positive and negative**

The contrastive score (`pos_score - neg_penalty × neg_score`) works well when the target code is structurally close to either the positive or negative corpus example. When the target code uses different variable names, different middleware chaining, or a different framework version from any corpus example, both `pos_score` and `neg_score` drop — and the contrastive signal collapses. This is a fundamental limitation of the fixed-corpus approach, not a tuning problem.

**4. The taint-required row is not a net win**

`Frensense + taint required` achieves 50% precision — the only row above Semgrep's precision. But at 24.3% recall, it misses 3 in 4 real bugs. A tool that achieves 50% precision at 24% recall is less useful than one that achieves 38% precision at 48% recall, because the first misses far more actionable vulnerabilities. Precision without recall is not a useful operating point for a security scanner.

### What this means for the system

The benchmark exposes a structural problem: **the corpus is the binding constraint, not the algorithm**. The MinHash LSH + 15D scoring + composition pipeline is sound, but sound machinery applied to insufficient training data produces insufficient results.

The correct path forward is not to tune thresholds — it is to grow the corpus. A corpus of ~3,000 well-authored pattern pairs would give the engine a realistic chance of matching Semgrep's recall. Combined with taint verification (which Semgrep does not have natively), it could then exceed Semgrep's precision at the same recall level.

**The current system should be understood as a proof of concept for the detection architecture, not a production-ready replacement for rule-based tools.**

---

## Known Recall Gaps

Categories where Frensense misses vulnerabilities systematically:

| Category | Miss Rate | Reason |
|---|---|---|
| Template injection (SSTI) | ~80% | Sparse corpus coverage — few example pairs |
| Logic bugs (auth bypass via race condition) | ~100% | Cannot be detected statically without temporal analysis |
| Deserialization vulnerabilities | ~60% | Framework-specific, hard to generalize |
| Second-order injection | ~70% | Requires multi-function taint path (cross-file limitation) |
| Mass assignment | ~40% | Requires schema-aware type resolution |
