# Crate: `frensense-bundler` — Corpus Compiler

**Path:** `frensense-bundler/src/`  
**Role:** Offline tool. Converts a directory of `*_positive.*` / `*_negative.*` file pairs into a `.frc` binary bundle.

---

## Purpose

The bundler is the "training" phase of Frensense. It:

1. Reads raw corpus example files from `corpus/targets/`.
2. Fingerprints all of them using the engine.
3. Learns per-category feature weights that maximally separate positives from negatives.
4. Derives semantic filter constraints automatically from the positive/negative contrast.
5. Fits per-pattern sigmoid calibration parameters.
6. Serializes everything into a signed `.frc` binary that the scanner loads at startup.

Running the bundler is required whenever corpus files are added or modified.

```bash
frensense --build-bundle --corpus corpus/targets/
```

---

## Build Pipeline (`builder.rs`)

```
corpus/targets/
      │
      ▼
1. load_corpus() — scan directory, pair positive/negative files by naming convention
      │
      ▼
2. analyze_file() for every corpus file → Vec<FunctionFingerprint>
      │
      ▼
3. compute_bundle_api_idf() — IDF weights for API call hashes across all corpus fingerprints
      │
      ▼
4. learn_category_weights() — per-category 15-d weight optimization
      │
      ▼
5. compute_auto_filters() — derive SemanticFilter constraints from positive/negative contrast
      │
      ▼
6. fit calibration — per-pattern sigmoid A, B parameters
      │
      ▼
7. learned_semantic_markers — discover which API calls appear in which vulnerability categories
      │
      ▼
8. BundlePayload { patterns, weights, filters, calibration, markers, idf_weights }
      │
      ▼
9. frensense_frc::write_bundle() → frensense-corpus.frc
```

---

## Module: `loader/`

### Corpus File Naming Convention

Pattern files must follow this naming scheme:

```
{lang}_{category}_{variant}_positive.{ext}
{lang}_{category}_{variant}_negative.{ext}
```

Examples:
```
ts_sqli_nosql_where_positive.ts
ts_sqli_nosql_where_negative.ts
rs_path_traversal_positive.rs
rs_path_traversal_negative.rs
```

The loader recursively scans the corpus directory, pairs files by name (strip `_positive`/`_negative`), and constructs `BundlePattern` objects.

### `[frensense]` Comment Block Parsing

Pattern metadata is parsed directly from the positive source file's `[frensense]` comment block using the tree-sitter AST. No sidecar TOML/YAML files.

```typescript
// [frensense]
// observation: User-controlled URL is passed to fetch() without validation.
// impact: Server can be used as proxy to reach internal services.
// improvement: Validate URL against an allowlist before fetching.
// cwe: CWE-918
// cvss: 8.8
// owasp: A10:2021
// severity: critical
// runtime_probe: ssrf
// tier: 1
```

Supported fields: `observation`, `impact`, `improvement`, `cwe`, `cvss`, `owasp`, `severity`, `runtime_probe`, `tier`, `exploit_scenario`, `reference`.

Template interpolation is supported: `{{ source }}` and `{{ sink }}` are replaced at finding-emit time with the actual taint source and sink names from the match evidence.

---

## Module: `auto_filter.rs` — Discriminative Filter Learning

### What It Does

For each corpus pattern pair, the auto-filter analyzer extracts structural features that distinguish the positive (vulnerable) from the negative (safe) version. These become `SemanticFilter` constraints.

### Algorithm

**Positive-exclusive call targets** → `contains_call_to`:
- Extract all function call targets from ALL positive files.
- Extract all function call targets from ALL negative files.
- `contains_call_to = pos_calls - neg_calls` (calls that appear in positives but not negatives).

**Negative-exclusive call targets** → `must_not_contain_call_to`:
- `must_not_contain_call_to = neg_calls - pos_calls` (calls exclusive to negatives).

**Node type exclusions** → `must_not_contain_node_type`:
- Extract AST keyword tokens (try/catch blocks, sanitizer patterns) from negatives.
- If a token appears in ALL negatives but no positives, add it as an exclusion.

**Function name patterns** → `must_not_match_function_name`:
- If ALL negative files contain functions matching a naming pattern absent from positives, exclude it.

### What Was Intentionally Removed

The category-level cross-pattern exclusivity loop was removed. Grouping patterns by category prefix (e.g., `"ns"`) and learning shared constraints caused every pattern in a category to require the same imports even when only a subset used them. Per-pattern negative-exclusivity is the correct mechanism.

### CS Theory

This is **discriminative feature selection** — finding features that distinguish class A (positive/vulnerable) from class B (negative/safe). Analogous to:
- Naive Bayes feature selection: keep features with high mutual information with the class label.
- SVM support vectors: the constraints act as the margin boundary.

The key difference from supervised ML: the "features" here are boolean (call present/absent), and the "classifier" is a conjunction of constraints — no probability distribution needed.

---

## Module: `pattern/weight_learner.rs` — Per-Category Weight Learning

### What It Does

For each vulnerability category (e.g., `"sqli"`, `"ssrf"`, `"cmdi"`), learn a 15-element weight vector `w ∈ ℝ^15` such that:

```
score(positive, w) > score(negative, w)
```

for the maximum number of corpus pairs.

### Algorithm

Uses a simple gradient-free approach:
1. For each category, collect all (positive_fp, negative_fp) pairs.
2. Score each pair using the default weights.
3. For pairs where positive score ≤ negative score (incorrectly ranked), adjust weights to increase the incorrectly-scored dimensions.
4. Iterate to convergence or a fixed number of epochs.

The learned weights are stored in `category_weights: HashMap<String, [f64; 15]>` inside `PatternRegistry`.

### Why Not Gradient Descent?

Gradient descent requires differentiating through the Jaccard similarity function, which involves set intersection/union operations on integer hash vectors. These are not differentiable. The current approach is a perceptron-style update rule that works well on the relatively small corpus sizes (typically 100-500 patterns).

---

## Module: `calibration.rs` — Sigmoid Calibration

### Purpose

Raw similarity scores are not calibrated probabilities. A score of 0.7 does not mean 70% confidence. Sigmoid calibration fits a function:

```
P(match | score) = σ(A · score + B) = 1 / (1 + e^{-(A·score + B)})
```

### Fitting

For each pattern, run the scorer on all corpus positive and negative fingerprints, collect `(score, label)` pairs where `label = 1` for positives and `label = 0` for negatives. Fit `(A, B)` using maximum likelihood estimation (logistic regression without regularization, since the corpus is small).

The fitted parameters are stored in `pattern_calibration: HashMap<String, (f32, f32)>`.

**CS Theory:** Platt scaling, probability calibration, logistic regression, maximum likelihood estimation.

---

## Bundle Payload (`BundlePayload`)

```rust
pub struct BundlePayload {
    pub patterns:                 Vec<BundlePattern>,
    pub category_weights:         Vec<(String, [f64; 15])>,
    pub auto_filter_stats:        Option<AutoFilterStats>,
    pub pattern_calibration:      HashMap<String, (f32, f32)>,
    pub learned_semantic_markers: HashMap<String, String>,
    pub api_idf_weights:          HashMap<u64, f32>,
}
```

All fields are serialized together and signed with BLAKE3. The engine deserializes this once at startup and populates `PatternRegistry`.
