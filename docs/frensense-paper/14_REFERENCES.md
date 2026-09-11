# References and Bibliography

This document lists all academic papers, datasets, and software libraries referenced in the Frensense system design.

---

## Core Algorithms

### Locality-Sensitive Hashing and MinHash

**Broder, A. Z. (1997)**  
"On the resemblance and containment of documents."  
*Proceedings of the Compression and Complexity of Sequences 1997 (SEQUENCES '97)*, pp. 21–29. IEEE.  
→ Original MinHash paper. Proves `P[min(π(A)) = min(π(B))] = J(A, B)`.

**Indyk, P. and Motwani, R. (1998)**  
"Approximate nearest neighbors: towards removing the curse of dimensionality."  
*Proceedings of the 30th Annual ACM Symposium on Theory of Computing (STOC '98)*, pp. 604–613.  
→ Foundational LSH theory: amplification via banding, S-curve analysis.

**Gionis, A., Indyk, P., and Motwani, R. (1999)**  
"Similarity search in high dimensions via hashing."  
*Proceedings of the 25th International Conference on Very Large Data Bases (VLDB '99)*, pp. 518–529.  
→ Practical banded LSH implementation guidance.

### Universal Hashing

**Dietzfelbinger, M., Karlin, A., Mehlhorn, K., Meyer auf der Heide, F., Rohnert, H., and Tarjan, R. E. (1997)**  
"A reliable randomized algorithm for the closest-pair problem."  
*Journal of Algorithms*, 25(1):19–51.  
→ Defines multiply-shift universal hash family: `h(x) = (a·x + b) mod 2^64` with odd `a`. Used in `minhash.rs`.

**Carter, J. L. and Wegman, M. N. (1979)**  
"Universal classes of hash functions."  
*Journal of Computer and System Sciences*, 18(2):143–154.  
→ Original universal hashing paper.

---

## Program Analysis

### Taint Analysis

**Newsome, J. and Song, D. (2005)**  
"Dynamic taint analysis for automatic detection, analysis, and signature generation of exploits on commodity software."  
*Proceedings of the 12th Annual Network and Distributed System Security Symposium (NDSS '05)*.  
→ Defines dynamic taint tracking. Frensense's static taint analysis adapts the same source/sink/sanitizer model.

**Livshits, V. B. and Lam, M. S. (2005)**  
"Finding security vulnerabilities in Java applications with static analysis."  
*Proceedings of the 14th USENIX Security Symposium*, pp. 271–286.  
→ Static taint analysis for web application security. Closest paper to Frensense's intraprocedural taint model.

**Denning, D. E. (1976)**  
"A lattice model of secure information flow."  
*Communications of the ACM*, 19(5):236–243.  
→ Original information flow lattice. The `TaintRegistry` scope-stack is an instance of the Denning lattice with `Tainted > Untainted` as the ordering.

### Control Flow Analysis

**Allen, F. E. (1970)**  
"Control flow analysis."  
*SIGPLAN Notices*, 5(7):1–19.  
→ Original CFG construction paper. The `BasicBlock` and `CFEdgeKind` definitions are standard Allen-style.

**Cooper, K. D., Harvey, T. J., and Kennedy, K. (2001)**  
"A simple, fast dominance algorithm."  
*Software—Practice and Experience*, 4(1):1–10. Rice University Technical Report CS-06-33406.  
→ The iterative dominance algorithm used in `cfg/mod.rs::BasicBlock.dominators` computation.

### Reaching Definitions and Def-Use Chains

**Aho, A. V., Lam, M. S., Sethi, R., and Ullman, J. D. (2006)**  
*Compilers: Principles, Techniques, and Tools* (2nd ed.).  
Pearson Education.  
→ The "Dragon Book." Reference for reaching definitions dataflow analysis (`cfg/def_use.rs`).

**Ryder, B. G. (1979)**  
"Constructing the call graph of a program."  
*IEEE Transactions on Software Engineering*, SE-5(3):216–226.  
→ Call graph construction. Frensense uses a simplified name-based approximation of this.

### Tree Edit Distance

**Zhang, K. and Shasha, D. (1989)**  
"Simple fast algorithms for the editing distance between trees and related problems."  
*SIAM Journal on Computing*, 18(6):1245–1262.  
→ The Zhang-Shasha TED algorithm. `ast_distance.rs` implements a simplified variant on extracted skeletons.

### Program Slicing

**Weiser, M. (1984)**  
"Program slicing."  
*IEEE Transactions on Software Engineering*, SE-10(4):352–357.  
→ Original program slicing paper. `corpus/flow_fingerprint.rs` implements a lightweight non-PDG-based approximation of backward slicing.

### Interprocedural Analysis

**Grove, D., DeFouw, G., Dean, J., and Chambers, C. (1997)**  
"Call graph construction in object-oriented languages."  
*ACM SIGPLAN Notices*, 32(10):108–124.  
→ Call graph precision levels (CHA, RTA, etc.). Frensense operates at approximately the CHA precision level for its name-based call graph.

---

## Information Retrieval

### TF-IDF

**Sparck Jones, K. (1972)**  
"A statistical interpretation of term specificity and its application in retrieval."  
*Journal of Documentation*, 28(1):11–21.  
→ Original TF-IDF paper. The `compute_idf_weights()` function in `fingerprint/types.rs` implements this exactly.

### Document Similarity and Shingling

**Broder, A. Z., Glassman, S. C., Manasse, M. S., and Zweig, G. (1997)**  
"Syntactic clustering of the Web."  
*Proceedings of the 6th International World Wide Web Conference (WWW '97)*, pp. 391–404.  
→ W-shingling for document similarity. Frensense applies this to token sequences of function bodies.

---

## Machine Learning

### Contrastive Learning and Metric Learning

**Chopra, S., Hadsell, R., and LeCun, Y. (2005)**  
"Learning a similarity metric discriminatively, with application to face verification."  
*Proceedings of the 2005 IEEE Computer Society Conference on Computer Vision and Pattern Recognition (CVPR '05)*, pp. 539–546.  
→ Contrastive loss. The (positive, negative) corpus pair training in Frensense maps to this framework.

**Schroff, F., Kalenichenko, D., and Philbin, J. (2015)**  
"FaceNet: A unified embedding for face recognition and clustering."  
*Proceedings of IEEE CVPR 2015*, pp. 815–823.  
→ Triplet loss. The contrastive scoring formula in `scorer.rs` is a direct analog of the triplet margin loss.

### Probability Calibration

**Platt, J. C. (1999)**  
"Probabilistic outputs for support vector machines and comparisons to regularized likelihood methods."  
In A. J. Smola, P. L. Bartlett, B. Schölkopf, and D. Schuurmans (Eds.), *Advances in Large Margin Classifiers*, pp. 61–74. MIT Press.  
→ Platt scaling (sigmoid calibration). The per-pattern calibration in `frensense-bundler/src/calibration.rs` implements this.

---

## Formal Methods

### Linear Temporal Logic

**Pnueli, A. (1977)**  
"The temporal logic of programs."  
*Proceedings of the 18th Annual Symposium on Foundations of Computer Science (FOCS '77)*, pp. 46–57. IEEE.  
→ Original LTL paper. The temporal property checker in `src/temporal/analyzer.rs` implements `G(A → F(B))` properties.

**Clarke, E. M. and Emerson, E. A. (1981)**  
"Design and synthesis of synchronization skeletons using branching time temporal logic."  
*Workshop on Logic of Programs*, LNCS 131, pp. 52–71. Springer.  
→ Model checking foundations.

---

## Datasets and Corpora

**Moonen, L., Vidziunas, L., and Bhandari, G. P. (2024)**  
"CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software" (v1.0.8).  
*17th International Conference on Predictive Models and Data Analytics in Software Engineering (PROMISE)*, Athens, Greece. Zenodo.  
DOI: https://doi.org/10.5281/zenodo.13138703  
→ Source of many corpus positive/negative pairs. CVE fix commits from open-source repositories.

**Semgrep, Inc. (2024)**  
*Semgrep Rules Repository*.  
GitHub. https://github.com/semgrep/semgrep-rules  
→ Source of additional pattern inspiration. Frensense patterns are rewritten as concrete code example pairs rather than DSL rules.

**OWASP Foundation (2023)**  
*OWASP Juice Shop* (v15.x).  
GitHub. https://github.com/juice-shop/juice-shop  
→ Primary benchmark target. Intentionally vulnerable TypeScript/Node.js web application.

**OWASP Foundation (2023)**  
*OWASP NodeGoat*.  
GitHub. https://github.com/OWASP/NodeGoat  
→ Secondary benchmark target. Intentionally vulnerable Node.js/MongoDB application.

---

## Software Dependencies

Key libraries used in the implementation:

| Library | Version | Purpose |
|---|---|---|
| `tree-sitter` | 0.22 | Parsing all supported languages |
| `petgraph` | 0.6 | Call graph (directed graph, BFS/DFS) |
| `rayon` | 1.8 | Data-parallel file and function analysis |
| `rustc-hash` (`FxHashMap`) | 1.1 | Fast non-cryptographic hash maps |
| `bincode` | 2.0 | Binary serialization of bundle payloads |
| `blake3` | 1.5 | Cryptographic checksum for `.frc` bundles |
| `oxc_*` | 0.14 | JavaScript/TypeScript compiler (AST + module resolution) |
| `serde` / `serde_json` | 1.0 | JSON serialization (MCP, SARIF output) |
| `lru` | 0.12 | `TaintCache` LRU eviction |
| `walkdir` | 2.4 | Recursive file system traversal |
| `clap` | 4.4 | CLI argument parsing |
| `tracing` | 0.1 | Structured logging (composition decisions, taint walks) |
| `criterion` | 0.5 | Benchmarking framework |
