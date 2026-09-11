# Theory Map: CS Concepts in Frensense

Every significant algorithmic decision in Frensense maps to an established computer science concept. This document lists them, where they appear in the code, and how they are applied.

---

## 1. Locality-Sensitive Hashing (MinHash + Banded LSH)

**CS Field:** Approximate algorithms, similarity search, randomized algorithms

**Where in code:**
- `frensense-engine/src/minhash.rs` — MinHash computation, LSH banding, `LSHIndex`
- `frensense-engine/src/corpus/registry.rs` — LSH index construction and candidate retrieval

**Theory:**

MinHash approximates the Jaccard coefficient without computing the exact set intersection:

```
J(A, B) = |A ∩ B| / |A ∪ B|
```

For a random permutation `π` of the universe: `P[min(π(A)) = min(π(B))] = J(A, B)`.

Banded LSH amplifies the signal: with `b` bands of `r` rows each:
```
P[collision in ≥ 1 band] = 1 - (1 - J^r)^b
```

This creates an S-curve in collision probability vs. Jaccard — near-zero below the threshold, near-one above it.

**Current parameters:**
- 120 hash functions (120-dimensional signature)
- 40 bands, 12 rows per band
- Threshold ≈ 0.71 at 50% recall

**Why this matters:** Without LSH, corpus matching would be O(N × P) where N = functions and P = patterns. LSH reduces this to O(N × candidates) where `candidates ≪ P` — enabling sub-second scans on large codebases.

**Key papers:** Broder 1997, Indyk & Motwani 1998.

---

## 2. Taint Analysis (Information Flow Analysis)

**CS Field:** Program analysis, security, information flow control

**Where in code:**
- `frensense-engine/src/data_flow/` — 13 modules covering the full taint pipeline
- `src/semantics/simple_taint.rs` — intraprocedural taint rule
- `src/semantics/data_flow/` — interprocedural taint rule

**Theory:**

Taint analysis is an **information flow** technique: it tracks *labels* (taint marks) propagated through program operations according to a *taint policy*. The fundamental question: "Can data from source `s` reach sink `k` without passing through a sanitizer?"

**Frensense uses May-Taint (sound, not complete):** If there exists *any path* in the CFG along which tainted data could reach the sink, the function is flagged. This errs on the side of more warnings (false positives are possible, false negatives are not).

**Scope stack lattice:** `TaintRegistry` implements a scope stack where the join of tainted and untainted is tainted. This is the standard over-approximation for conditional sanitization:

```
if (safe) {
    x = sanitize(y);  // y is untainted in this branch
} else {
    x = y;            // y is still tainted here
}
// At join point: x is TAINTED (conservative)
```

**Key papers:** Newsome & Song 2005, Livshits & Lam 2005.

---

## 3. Control Flow Graphs and Dominance Analysis

**CS Field:** Compiler construction, program analysis

**Where in code:**
- `frensense-engine/src/cfg/mod.rs` — `ControlFlowGraph`, `BasicBlock`, `CFEdgeKind`
- `frensense-engine/src/cfg/def_use.rs` — reaching definitions, def-use chains

**Theory:**

A **Control Flow Graph (CFG)** `G = (V, E)` has a vertex per basic block and edges per control transfer. Basic blocks are maximal straight-line sequences with a single entry and single exit.

**Dominance:** Node `d` *dominates* node `n` if every path from the program entry to `n` passes through `d`. Frensense uses dominance to verify that auth checks *must* execute before sensitive operations — if the auth check doesn't dominate the sensitive op, there's a bypass path.

**Reaching Definitions:** A definition `d: x = e` at node `n` *reaches* node `m` if there is a CFG path from `n` to `m` along which `x` is not redefined. Implemented as:
```
IN[B]  = ∪ OUT[pred(B)]
OUT[B] = gen[B] ∪ (IN[B] - kill[B])
```

**Key papers:** Cooper et al. 2001 ("A Simple, Fast Dominance Algorithm"), Allen 1970.

---

## 4. Tree Edit Distance

**CS Field:** String/tree algorithms, bioinformatics, AST analysis

**Where in code:**
- `frensense-engine/src/ast_distance.rs` — skeleton extraction and TED computation

**Theory:**

**Tree Edit Distance (TED)** measures the minimum number of node insertions, deletions, and relabelings to transform one labeled ordered tree into another.

Frensense uses a simplified variant:
1. Extract the structural *skeleton* of each function: ordered sequence of normalized node kinds, stripping identifiers and literals.
2. Node normalization: all loops → `loop_node`, all branches → `branch_node`, all try blocks → `try_node`. This collapses syntactic variation across languages.
3. Compute TED on the normalized skeletons.

The normalization step is essential: without it, `while` and `for` loops would have TED = 1 (one relabeling), when they are semantically equivalent and should have TED = 0.

**CS Theory:** Zhang-Shasha algorithm (1989), O(n²m²) worst case.

---

## 5. TF-IDF Weighting

**CS Field:** Information retrieval, text mining

**Where in code:**
- `frensense-engine/src/fingerprint/types.rs` — `compute_idf_weights()`, `apply_idf_weights()`
- `frensense-engine/src/corpus/registry.rs` — `idf_weights`, `api_idf_weights`

**Theory:**

**TF-IDF (Term Frequency–Inverse Document Frequency)** weights tokens by their discriminative power:
```
IDF(token) = log(N / df(token))
```
where N = total documents (functions) and df(token) = number of documents containing the token.

In Frensense, each function is a "document" and each n-gram hash is a "term." Common boilerplate tokens (e.g., `import express from "express"`) appear in many functions → low IDF → low weight. Rare security-sensitive tokens (e.g., `execSync`, `db.query.raw`) appear in few functions → high IDF → high weight.

The weighted Jaccard similarity uses IDF-weighted overlap rather than raw set size, making rare shared tokens count more than common ones.

**Key paper:** Sparck Jones 1972.

---

## 6. Multi-Dimensional Weighted Similarity Scoring

**CS Field:** Information retrieval, metric learning, pattern recognition

**Where in code:**
- `frensense-engine/src/pattern/similarity.rs` — `RawDimensions`, `weighted_score()`
- `frensense-engine/src/pattern/scorer.rs` — `PatternScorer`, `ScorerConfig`

**Theory:**

The final score is a **linear combination** of similarity scores across 15 independent dimensions:
```
vuln_score = Σ_{i=0}^{14} w_i · sim_i
```

The weights `w` are learned per vulnerability category. The **identity gate** is a multiplicative pre-condition that prevents matches on code that shares n-grams but lacks any identity-bearing signal:

```
gate = min(max(api_sim, semantic_sim, ast_sim, motif_sim, flow_sim) × 2.5 + 0.1, 1.0)
final = vuln_score × gate
```

This is related to **weighted Jaccard similarity** and **multivariate scoring** in retrieval systems.

**Issue visible in code:** The gate formula `identity_gate * 2.5 + 0.1` adds a floor of 0.1, meaning a function with *zero* identity signal still passes 10% of the gate. This is a known FP contributor — see [`12_LIMITATIONS.md`](./12_LIMITATIONS.md).

---

## 7. Contrastive Learning (Discriminative Pattern Matching)

**CS Field:** Metric learning, discriminative training

**Where in code:**
- `frensense-engine/src/pattern/scorer.rs` — contrastive scoring
- `frensense-bundler/src/pattern/weight_learner.rs` — weight optimization
- `frensense-bundler/src/auto_filter.rs` — discriminative feature selection

**Theory:**

Standard similarity matching asks: "How similar is the target to the known pattern?"  
Contrastive matching asks: "Is the target *more similar to the vulnerable version* than to the safe version?"

```
contrastive_score = pos_score - neg_penalty_weight × neg_score
```

This is analogous to:
- **Triplet loss** in metric learning: anchor (pattern), positive (vulnerable), negative (safe).
- **Discriminative training** in HMMs: maximize `P(vulnerable | features) - P(safe | features)`.
- **Contrastive loss** (Chopra et al. 2005): minimize distance for same-class pairs, maximize for different-class.

The key insight: the negative example provides the *boundary* — the structurally identical but safe version that defines what "safe" looks like for this pattern. Without the negative, false positives arise from functions that are structurally similar to the positive but are actually safe.

**Key papers:** Chopra et al. 2005, Schroff et al. 2015 (FaceNet).

---

## 8. Multi-Layer Confidence Composition (AND-Gate Verification)

**CS Field:** Fault-tolerant systems, evidence combination, multi-sensor fusion

**Where in code:**
- `src/engine/composition.rs` — `compose_confidence()`, `LayerSignals`

**Theory:**

The composition model is a **4-layer AND-gate**: a finding is only trusted when multiple independent evidence sources agree.

```
Layer 1 (L1): Corpus match  — structural similarity
Layer 2 (L2): Taint flow    — data flow confirmation
Layer 3 (L3): Validator     — suppressor (negative evidence)
Layer 4 (L4): Near-dup      — amplifier (consistency evidence)
```

This is related to:
- **Bayesian evidence combination:** each layer updates a prior probability.
- **Dempster-Shafer theory:** combining evidence from independent sources.
- **Multi-sensor fusion:** in avionics/robotics, critical decisions require agreement from independent sensors.

The deterministic rule implementation (rather than probabilistic Bayesian updating) is intentional for auditability — every score adjustment has a named, documented cause.

---

## 9. Call Graph Construction (Interprocedural Analysis)

**CS Field:** Compiler theory, program analysis

**Where in code:**
- `frensense-engine/src/graph.rs` — `SemanticGraph` (petgraph DiGraph)
- `frensense-engine/src/data_flow/cross_file.rs` — interprocedural taint resolver

**Theory:**

A **call graph** `CG = (F, E)` where F = functions, E = call relations. For a language without dynamic dispatch, an exact call graph can be built statically. For JavaScript/TypeScript, call graph construction is inherently imprecise due to:
- First-class functions
- Dynamic `require()`
- Prototype inheritance
- Event-driven dispatch

Frensense uses a **name-based approximation**: call edges are established by matching call site names to function definitions by name within the project. This is roughly at the precision level of **CHA (Class Hierarchy Analysis)** — fast but may create phantom edges.

The call graph is used for:
- Cross-file taint propagation (BFS over `Calls` edges)
- Function reachability queries
- Temporal property checking (are operations `A` and `B` reachable in the same call chain?)

**Key papers:** Ryder 1979, Grove et al. 1997.

---

## 10. Linear Temporal Logic (LTL) Property Checking

**CS Field:** Formal verification, model checking

**Where in code:**
- `src/temporal/analyzer.rs` — sequence property checker
- `src/temporal/config.rs` — built-in temporal rules

**Theory:**

**Linear Temporal Logic (LTL)** extends propositional logic with temporal operators:
- `G φ` — φ holds globally (on all future states)
- `F φ` — φ holds eventually (on some future state)
- `X φ` — φ holds in the next state
- `φ U ψ` — φ holds until ψ holds

Frensense checks properties of the form: `G(A → F(B))` — "globally, whenever A occurs, B eventually follows." For example:

```
G(fundWallet → F(createLedgerEntry))
```

"Whenever `fundWallet` is called, `createLedgerEntry` must eventually be called (in the same function)."

The implementation is **bounded model checking** restricted to a single function's execution trace, not full LTL model checking. This makes it tractable but misses inter-function sequencing properties.

**Key papers:** Pnueli 1977, Clarke & Emerson 1981.

---

## 11. Semantic Motifs and API Abstraction

**CS Field:** Abstract interpretation, program analysis vocabulary

**Where in code:**
- `frensense-engine/src/corpus/motifs.rs` — `MOTIFS` static table, `MOTIF_LOOKUP`
- `frensense-engine/src/corpus/flow_fingerprint.rs` — motif-based source/sink detection

**Theory:**

A **motif** is an equivalence class of API calls under semantic equivalence. Formally:

```
motif(call) = canonical_name if call ∈ motif_members
```

At fingerprint time:
```
hash("exec")     → hash("CommandExecutionSink")
hash("spawn")    → hash("CommandExecutionSink")
hash("Command::new") → hash("CommandExecutionSink")
```

This is analogous to:
- **Abstract interpretation:** replacing concrete values with abstract representatives.
- **Concept lattices:** grouping calls by their semantic category.
- **Defunctionalization:** replacing first-class function calls with tagged variants.

The key benefit: a pattern trained on one API (`exec`) automatically generalizes to semantically equivalent APIs (`spawn`, `system`, `execFile`) without any additional corpus examples. This is cross-framework and cross-language generalization at the semantic level.

---

## 12. Probability Calibration (Platt Scaling)

**CS Field:** Machine learning, statistics

**Where in code:**
- `frensense-bundler/src/calibration.rs` — sigmoid fitting
- `frensense-engine/src/corpus/registry.rs` — calibration application

**Theory:**

Raw similarity scores `s ∈ [0, 1]` are not calibrated probabilities. A score of 0.7 does not mean 70% probability. **Platt scaling** (also called logistic calibration) fits:

```
P(match | s) = σ(A·s + B) = 1 / (1 + e^{-(A·s + B)})
```

Parameters `(A, B)` are fit by maximum likelihood on a held-out validation set of (score, label) pairs. The fitted sigmoid maps raw scores to calibrated confidence values that are statistically meaningful.

Per-pattern calibration accounts for the fact that different patterns have different difficulty: a SQL injection pattern may need a raw score of 0.75 to achieve 0.65 confidence, while a hardcoded-secret pattern may achieve the same confidence at a raw score of 0.50.

**Key paper:** Platt 1999.

---

## 13. Shingling and Document Similarity

**CS Field:** Information retrieval, near-duplicate detection

**Where in code:**
- `frensense-engine/src/fingerprint/hashing.rs` — `token_ngrams_sorted()`, `token_ngrams_positional()`

**Theory:**

**Shingling** (w-shingling): represent a document as the set of all its overlapping w-token windows. For a token sequence `[t1, t2, t3, t4, t5]` with w=3:

```
shingles = {(t1,t2,t3), (t2,t3,t4), (t3,t4,t5)}
```

Frensense hashes each shingle to a `u64` and stores the set as `ngram_hashes`. Jaccard similarity between two shingle sets approximates the probability that a random position in both documents contains the same w-gram — a measure of content overlap.

Positional n-grams (used for `cf_order_sim`) include the position index: `hash(position, t_i, t_{i+1}, t_{i+2})`. These are not Jaccard-compatible but capture sequence order for cosine similarity computation.

---

## Summary Table

| CS Concept | Frensense Module | Purpose |
|---|---|---|
| MinHash LSH | `minhash.rs`, `registry.rs` | Sub-linear corpus retrieval |
| May-taint analysis | `data_flow/` | Source→sink flow detection |
| Scope-stack lattice | `data_flow/mod.rs::TaintRegistry` | Conservative taint propagation |
| Control flow graph | `cfg/mod.rs` | Path-sensitive analysis, dominator computation |
| Reaching definitions | `cfg/def_use.rs` | Def-use chains for taint |
| Tree edit distance | `ast_distance.rs` | Structural similarity (ast_sim dimension) |
| TF-IDF weighting | `fingerprint/types.rs` | Down-weight boilerplate tokens |
| Weighted linear scoring | `pattern/similarity.rs` | Multi-dimensional match confidence |
| Identity gate | `pattern/similarity.rs` | Prevent boilerplate false positives |
| Contrastive learning | `pattern/scorer.rs` | Positive vs. negative discrimination |
| Discriminative feature selection | `frensense-bundler/auto_filter.rs` | Auto-derive SemanticFilters |
| AND-gate evidence combination | `engine/composition.rs` | Multi-layer confirmation |
| Name-based call graph | `graph.rs`, `data_flow/cross_file.rs` | Interprocedural taint propagation |
| LTL sequence checking | `temporal/analyzer.rs` | Financial and auth invariants |
| API abstraction (motifs) | `corpus/motifs.rs` | Cross-framework generalization |
| Sigmoid calibration | `frensense-bundler/calibration.rs` | Convert scores to probabilities |
| W-shingling | `fingerprint/hashing.rs` | N-gram set representation |
| LRU cache | `src/lib.rs::TaintCache` | Taint walk memoization |
| Visitor pattern | `FrensenseRule::check` | AST rule dispatch |
| Strategy pattern | `LanguageSpec` trait | Language polymorphism |
