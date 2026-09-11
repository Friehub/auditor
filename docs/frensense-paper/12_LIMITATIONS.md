# Known Limitations and Open Problems

This document is the theoretical counterpart to `LIMITATIONS_MAP.md`. It frames each limitation in terms of the underlying CS theory, explains *why* the limitation exists, and proposes what would be needed to address it.

---

## L1: False Positive Rate in Structural-Only Mode

**Observed:** 25-34% precision on OWASP Juice Shop when taint verification is disabled or unavailable.

**Root Cause (Theory):**

Corpus matching operates on `FunctionFingerprint` similarity. Two functions sharing:
- The same library (Express)
- The same HTTP handler structure (`req` parameter, `res.json()` call)
- Some database interaction

…will score similarly even if one passes user input to a raw query and the other passes a validated value.

The 15-dimensional fingerprint captures *what APIs are called* and *what the structure looks like*, but **not what data flows through those APIs**. At the fingerprint level, "a handler that calls `db.query` with `req.body.id`" and "a handler that calls `db.query` with a sanitized literal" look nearly identical.

**What the identity gate does:** The multiplicative gate (max of `api_sim`, `semantic_sim`, `ast_sim`, `motif_sim`, `flow_sim`) mitigates this by requiring at least one identity-bearing dimension to agree. However, the gate formula adds a 0.1 floor:

```rust
let gate = (identity_gate * 2.5 + 0.1).min(1.0)
```

A function with `identity_gate = 0` still passes the gate at 0.1. This means 10% of the structural score leaks through even when no identity signal matches. For high-precision use cases, this floor should be 0.0.

**What would fix it:**  
1. Remove the 0.1 floor from the gate formula (risk: may drop recall on near-duplicate patterns where identity signals are weak by design).
2. Make taint verification mandatory for all corpus findings (current: taint is optional, penalty for absent taint is 0.6×, not 0.0×).
3. Require `flow_sim > 0` as a hard gate (current: flow_sim is a soft dimension).

---

## L2: Tainted API Call Detection is Heuristic

**Observed:** `tainted_api_calls` in `FunctionFingerprint` captures API calls where a *parameter name* appears as an argument. This is heuristic, not type-resolved.

**Root Cause (Theory):**

The taint extraction at fingerprint time does not run the full `DataFlowEngine`. It uses a lightweight approximation:

```
tainted_api_call = any API call where at least one argument string-matches a parameter name
```

This means:
- **False positive:** `doSomething(userId)` is flagged as tainted even if `userId` is not a request parameter but a locally-computed safe value.
- **False negative:** `doSomething(processedData)` is NOT flagged if the intermediate variable `processedData = clean(req.body.id)` is not a parameter name.

The full `DataFlowEngine` (in `data_flow/engine.rs`) does track intermediate assignments, but it is run at scoring time (after LSH pre-filtering) and is therefore too slow to run during fingerprint extraction for the entire codebase.

**What would fix it:**  
Compute `tainted_api_calls` from the `SemanticOp` IR during `analyze_file()` using the `TaintRegistry` instead of the parameter-name heuristic. The `SemanticOp` normalisation already exists — the integration is missing.

---

## L3: Cross-File Taint Breaks After 2-3 Hops

**Observed:** Interprocedural taint paths spanning more than 2-3 intermediate functions are often missed.

**Root Cause (Theory):**

The cross-file resolver (`data_flow/cross_file.rs`) builds taint propagation using a **name-based call graph**. Call edges are established by matching callee names to function definitions. This fails when:
- Functions are passed as callbacks: `router.get('/path', handlerFn)` — the call edge to `handlerFn` is missed if `handlerFn` is defined elsewhere and not obviously called.
- Dynamic dispatch: `this.service[method]()` — no static edge.
- Higher-order functions: `arr.map(transform)` — `transform` is not resolved.

At 3+ hops, the chance of at least one name-resolution failure accumulates. The taint propagation chain breaks and the `TaintOrigin` is lost.

**What would fix it:**  
1. Use `OxcProvider` for JS/TS (exact module resolution already built — just not yet used for call graph construction, only for source/sink classification).
2. Implement **callback registration tracking**: when `app.get(path, fn)` is seen, add a `Calls` edge from the route to `fn`.
3. Use **function summary propagation**: if function F returns a value that is tainted from one of its parameters, store this as a summary and use it at call sites.

---

## L4: Hollow Validator Suppression (L3) Incorrectly Suppresses IDOR-Style Findings

**Observed:** Functions that branch on a tainted `user.role` check and then pass a different tainted parameter (`user.id`) to a DB query get suppressed by L3.

**Root Cause (Theory):**

The L3 suppression logic:
```
if branch_ratio > 0.85 AND has_validation_name → suppress × 0.3
```

The `has_validation_name` check uses the function name (e.g., `updateUser`, `handleRequest`). "Validator" names include `validate_*`, `check_*`, `verify_*`. But an IDOR-vulnerable handler like `handleUserDataUpdate` does not have a validator name — so this case *should* be fine.

The actual issue: the branch-ratio threshold of 0.85 was raised from 0.6 in v0.5.3, but there is no test that covers a function with `branch_ratio > 0.85` and `has_validation_name = false` that *does* contain a real vulnerability. The existing test coverage only verifies that genuine validators ARE suppressed and that low-ratio functions are NOT suppressed.

**What would fix it:**  
Add an integration test for an IDOR-style function: `branch_ratio = 0.91, has_validation_name = false, taint_path = confirmed`. Verify the finding survives composition. This is a test coverage gap, not a logic bug.

---

## L5: Weight Learning Does Not Use Gradient Descent

**Observed:** Per-category weights are learned via a perceptron-style update rule, not gradient descent.

**Root Cause (Theory):**

The Jaccard similarity function on sorted integer sets is not differentiable in the standard sense. It operates on sorted `Vec<u64>` — the intersection/union size is computed via merge-join and is not a continuous function of its inputs. Therefore, standard gradient descent (which requires computing ∂Loss/∂w_i) cannot be applied directly.

The current approach (grid search / perceptron update) works for small corpus sizes (100-500 patterns) but becomes computationally expensive at scale. Worse, it may converge to a local optimum rather than the global optimum for the 15-dimensional weight space.

**What would fix it:**  
1. **Differentiable approximation:** Replace sorted-set Jaccard with soft Jaccard using sigmoid-smoothed set membership functions.
2. **Pairwise ranking loss:** Use a ranking loss `max(0, 1 - (pos_score - neg_score))` which is subgradient-differentiable.
3. **Coordinate descent:** For each weight dimension independently, do a 1D grid search — this scales linearly rather than exponentially.

---

## L6: MinHash Hash Function Quality

**Observed:** The current multiply-shift hash family generates hash values with correlations at high bit positions for small values.

**Root Cause (Theory):**

The hash function is:
```rust
let a = (seed.wrapping_mul(0x517cc1b727220a95).wrapping_add(1)) | 1;
let b = seed.wrapping_mul(0x9e3779b97f4a7c15);
value.wrapping_mul(a).wrapping_add(b)
```

Multiply-shift is 2-universal but NOT 4-universal. For LSH quality guarantees, 2-universality is sufficient in theory, but in practice with small corpus sizes and small n-gram hash universes (n-grams of common tokens), hash collisions between distinct tokens can inflate the measured Jaccard similarity.

The code comment in `minhash.rs` notes: "prefer `XxHash64::with_seed` if available." XXH3 with per-row seeds would be empirically better with equivalent asymptotic guarantees.

**Impact:** Minor — current precision/recall suggests the hash quality is acceptable at the current corpus size. May become a bottleneck at corpus sizes > 5000 patterns.

---

## L7: No Cross-Language Taint Tracking

**Observed:** Taint does not propagate across language boundaries.

**Root Cause:** The engine processes each language independently. A TypeScript handler calling a Rust FFI function via `napi-rs` bindings is treated as two separate call chains with no cross-language link.

**Impact:** Multi-language projects (e.g., a Node.js frontend calling a Rust backend via NAPI) cannot be fully analyzed. The Rust backend functions that receive data from the TypeScript layer are not marked as taint sources.

**What would fix it:** This requires a foreign function interface (FFI) model — essentially annotating NAPI bindings as taint-propagating call edges. No straightforward solution exists without language-specific FFI knowledge.

---

## L8: Temporal Checker Is Bounded to Single-Function Scope

**Observed:** The temporal property checker only verifies event sequence properties within a single function body.

**Root Cause (Theory):**

Full LTL model checking over an interprocedural call graph is PSPACE-complete. The implementation uses a tractable approximation: check event sequences only within function bodies. This misses:

- `fundWallet()` called in one function, `createLedgerEntry()` called in another function called by the first.
- Any temporal property that requires tracking state across function call boundaries.

**What would fix it:** Bounded interprocedural LTL checking — unroll call chains up to depth N (e.g., 3) and check temporal properties on the resulting inlined sequence. Computationally expensive but feasible at bounded depth.

---

## L9: Pattern Calibration Overfits on Small Corpus

**Observed:** For patterns with fewer than 5 corpus examples, the sigmoid calibration parameters `(A, B)` can be fit to noise.

**Root Cause (Theory):**

Logistic regression with no regularization overfits when the training set is small. With 3-4 positive/negative examples, the sigmoid can fit the training data perfectly while generalizing poorly.

**What would fix it:** Add L2 regularization to the calibration fitting:
```
L = -Σ [y log(σ(Ax+B)) + (1-y) log(1-σ(Ax+B))] + λ(A² + B²)
```

Or use a Bayesian prior over `(A, B)` centered at `(1, 0)` (identity calibration) — patterns with few examples fall back toward uncalibrated scores rather than overfitting.

---

## Summary Table

| Limitation | Root Cause | Theoretical Fix |
|---|---|---|
| FP rate in structural-only mode | Gate floor 0.1 leaks structural score | Remove floor; require flow_sim > 0 |
| Tainted API heuristic | Parameter-name matching vs. data flow | Integrate TaintRegistry into fingerprint extraction |
| Cross-file taint at 3+ hops | Name-based call graph misses callbacks | Use OxcProvider for call graph construction |
| IDOR suppression test gap | Missing test coverage | Add integration test for IDOR with high branch ratio |
| Non-differentiable weight learning | Jaccard on integer sets | Differentiable Jaccard approximation or ranking loss |
| Hash family quality | Multiply-shift is 2-universal | Replace with XXH3 + per-row seeds |
| No cross-language taint | No FFI model | Annotate NAPI/C FFI bindings as taint propagators |
| Temporal check is single-function | LTL model checking is PSPACE-complete | Bounded interprocedural unrolling at depth 3 |
| Calibration overfit | No regularization on logistic regression | Add L2 regularization or Bayesian prior |
