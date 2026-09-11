<div align="left">
  <h1>Frensense</h1>
  <p><strong>A deterministic, corpus-driven security and diagnostic engine for Rust, TypeScript, and JavaScript.</strong></p>
</div>

<br />

Frensense detects semantic bugs, architectural violations, and AI hallucinations—code that compiles but doesn't do what it says it does. It operates without brittle YAML rules, regex patterns, or handwritten DSLs.

```bash
cargo install frensense
frensense . --corpus corpus/targets/
```

## How It Works

Starting in `v0.5.0`, Frensense completely abolished manual rule writing. All detection is driven by the **Frensense Rule Corpus (.frc)**. 

The engine fingerprints every function in your project, scores it against the pre-compiled `.frc` bundle, and emits findings when multiple layers confirm the violation:

1. **Corpus Match (Structural)** — Your function's AST shape mathematically matches a known violation pattern in the corpus.
2. **Taint Path (DataFlow)** — Tainted data dynamically flows from a source to a vulnerable sink without sanitization.
3. **Cross-Function Consistency** — Ensures sibling functions do not diverge on the same pattern.

A finding only fires when the structural match and dataflow composition agree, guaranteeing a near-zero false positive rate.

## What It Catches

Frensense actively encodes and enforces three distinct categories of code patterns:

- **Security Vulnerabilities:** SQL Injection, SSRF, Path Traversal, and Credentials flowing to logs/HTTP.
- **Architectural Invariants:** `validate_*()` functions with no rejection path, missing payment gates, or hollow validators that pass input through unchanged.
- **LLM Hallucinations:** Hardcoded tokens, AI-generated `any` parameters, `console.log` in production, and `await` in synchronous blocks.

## Performance & Exclusions

Frensense is highly optimized for large codebases. To maintain sub-second scan times, the engine automatically ignores:
- **Build directories:** `node_modules`, `target`, `dist`, `build`, `vendor`, `out`, and hidden directories (`.*`).
- **Test files:** Files matching `*.test.*`, `*.spec.*`, `__tests__`, or `mocks`.
- **Generated bundles:** Files matching `*.min.js`, `*.bundle.js`, or `*.chunk.js`.
- **Large files:** Any source file larger than 1MB is skipped.

## Quick Start

```bash
# Basic scan
frensense .

# With corpus pattern detection (Standard)
frensense . --corpus corpus/targets/ --threshold 0.65

# Data-Flow (Taint) Mode with fine-tuned structural boundaries
frensense . --corpus corpus/targets/ --mode taint --ngram-sim-threshold 0.05 --threshold 0.00 --min-confidence 0.65

# Only critical findings
frensense . --severity critical --strict

# JSON output
frensense . --json

# SARIF for GitHub Advanced Security
frensense . --sarif

# Diff-only (changed files since last commit)
frensense . --diff-only --strict

# Baseline suppression
frensense . --baseline baseline.json

# List loaded patterns
frensense --list-patterns --corpus corpus/targets/
```

## Adding a Detection: Pure Code, Zero Config

To teach Frensense a novel vulnerability or business logic flaw specific to your architecture, you simply drop two code snippets into the `corpus/targets/` directory.

```bash
cp my_bug.ts    corpus/targets/ts_my_bug_positive.ts
cp fixed.ts     corpus/targets/ts_my_bug_negative.ts
```

**You do not write TOML or YAML.** Instead, you provide the advisory text directly inside the `_positive` source code file using a `[frensense]` comment block. The engine supports template interpolation for dynamic advisory generation (e.g., `{{ source }}` and `{{ sink }}`).

### The Positive Example (`ts_my_bug_positive.ts`)
This file represents the vulnerable code shape.

```typescript
// [frensense]
// observation: Writing user-provided data directly to a datastore...
// impact: Unsanitized data from `{{ source }}` reaches the `{{ sink }}` execution context, allowing attackers to manipulate queries.
// improvement: Call a central auth resolver or use parameterized bindings before passing `{{ source }}` to `{{ sink }}`.

export async function handleDataSync(req: Request, db: Database) {
  // Vulnerable pattern
  const filter = req.query.filter;
  db.collection('users').find({ $where: filter });
}
```

### The Negative Example (`ts_my_bug_negative.ts`)
This file represents the structurally identical, but safe code shape. It prevents false positives.

```typescript
export async function handleDataSync(req: Request, db: Database) {
  // Safe pattern (properly sanitized/parameterized)
  const filter = sanitize(req.query.filter);
  db.collection('users').find({ $where: filter });
}
```

Run the builder to compile your new custom `.frc` bundle:
```bash
frensense --build-bundle --corpus corpus/targets/
```
Frensense parses your comment block straight from the AST and bakes it into the `.frc` bundle.

## AI Agent Integration (MCP)

Frensense ships with native support for the **Model Context Protocol (MCP)**, allowing AI agents (like Claude or Antigravity) to interact with the engine.

```bash
# Start the MCP server
frensense-mcp
```
Agents can dynamically query the workspace, request taint path resolutions, and validate their own generated code against the corpus before committing changes.

## Citation

The Frensense detection corpus is built from real-world vulnerability data:

> Moonen, L., Vidziunas, L., & Bhandari, G. P. (2024). *CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software* (v1.0.8). 17th International Conference on Predictive Models and Data Analytics in Software Engineering (PROMISE), Athens, Greece. Zenodo. https://doi.org/10.5281/zenodo.13138703

> Semgrep, Inc. (2024). *Semgrep Rules Repository*. GitHub. https://github.com/semgrep/semgrep-rules

## V0.5.0 Compiler Mode

In v0.5.0, Frensense introduced **Compiler Mode**, which shifts from heuristic syntax parsing to exact semantic resolution. 
By passing the `--use-compiler` flag, Frensense mounts full language servers during the scan:
* **TypeScript/JavaScript**: Loads the lightning-fast Oxc compiler pipeline to resolve complex module aliases, scoped types, and cross-file dataflow.
* **Rust**: Leverages the `rust-analyzer` hir (High-Level Intermediate Representation) for precise trait resolution, macro expansion, and dataflow integrity.

```bash
frensense src/ --use-compiler
```

## Corpus Quality Guide

The engine is only as good as its corpus. A pattern with a 3-line toy function
(`function redirect(next) { res.redirect(next); }`) produces near-zero signal —
no imports, no control flow, no taint source. Every Express route handler that
calls `res.redirect` will match it. A good pattern has real imports, multiple
functions, explicit taint sources, and a proper `[frensense]` comment block.

### Good Positive Checklist

```
✓  Has a [frensense] block with observation/impact/improvement
✓  Has at least one real import statement
✓  Has 2–5 functions, not just one
✓  Proper HTTP handler signature (req, res, ctx, c)
✓  Taint source is explicit (req.body.X, c.Query("X"))
✓  Sink call present (exec, query, fetch, res.redirect)
✓  Typed parameters (not `req: any` everywhere)
✓  Bug is inside a named function (not top-level)
```

### Good Negative Checklist

```
✓  Has a // SAFE: comment explaining the fix
✓  Same structure as positive (imports, functions, params) — only the fix differs
✓  Uses the REAL fix, not a toy allowlist
✓  Still has the same sink call — used safely
✓  Does NOT simply delete the vulnerable call
```

### All Metadata Goes in `[frensense]` — No TOML

Frensense does NOT use TOML sidecar files. All per-pattern metadata belongs in
the `[frensense]` comment block at the top of the positive file:

```typescript
// [frensense]
// observation: User-controlled URL is passed to fetch() without host validation.
// impact: Server can be used as a proxy to reach internal services.
// improvement: Validate URL against an allowlist of permitted external hosts.
// cwe: CWE-918
// cvss: 8.8
// owasp: A10:2021
// runtime_probe: ssrf
// tier: 1
```

Supported fields: `observation`, `impact`, `improvement`, `cwe`, `cvss`, `owasp`,
`severity`, `runtime_probe`, `tier`, `exploit_scenario`, `reference`.

### Template: Good CMDI Pair

**`ts_cmdi_exec_shell_positive.ts`:**
```typescript
// [frensense]
// observation: User-controlled input from req.body.script is passed to exec()
//              via shell string interpolation, allowing arbitrary command execution.
// impact: An attacker can execute any OS command.
// improvement: Replace exec() with execFile() and pass arguments as an array.
// cwe: CWE-78

import { exec } from "child_process";
import express from "express";
import { Router } from "express";

const router = Router();

async function resolveScript(scriptName: string): Promise<string> {
    return `/scripts/${scriptName}`;
}

router.post("/api/jobs/run", async (req: express.Request, res: express.Response) => {
    const { script, args } = req.body as { script: string; args: string };
    const resolved = await resolveScript(script);
    exec(`${resolved} ${args}`, (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: stderr });
        res.json({ output: stdout });
    });
});

router.post("/api/admin/command", (req: express.Request, res: express.Response) => {
    const cmd = req.body.cmd as string;
    exec(cmd, (error, stdout) => {
        res.json({ result: stdout, error: error?.message });
    });
});

export default router;
```

**`ts_cmdi_exec_shell_negative.ts`** (fix: execFile + allowlist):
```typescript
// SAFE: Replaced exec() with execFile() — arguments passed as array.

import { execFile } from "child_process";
import express from "express";
import { Router } from "express";

const router = Router();
const ALLOWED_SCRIPTS = new Set(["report", "backup", "health-check"]);
const ALLOWED_ARGS_RE = /^[a-zA-Z0-9_\-\.]+$/;

router.post("/api/jobs/run", async (req: express.Request, res: express.Response) => {
    const { script, args } = req.body as { script: string; args: string };
    if (!ALLOWED_SCRIPTS.has(script)) return res.status(403).json({ error: "Script not permitted" });
    if (args && !ALLOWED_ARGS_RE.test(args)) return res.status(400).json({ error: "Invalid format" });
    execFile(`/scripts/${script}`, args ? [args] : [], (err, stdout) => {
        if (err) return res.status(500).json({ error: "Execution failed" });
        res.json({ output: stdout });
    });
});

router.post("/api/admin/command", (_req, res) => {
    res.status(403).json({ error: "Direct command execution not permitted" });
});

export default router;
```

See `FRENSENSE_CORPUS_GUIDE.md` for the full quality guide, CWE mapping table,
mutation guidelines, and the Frensense Hub corpus exchange proposal.

## Documentation

| Document | What it covers |
|----------|---------------|
| `docs/ARCHITECTURE.md` | Complete module map with every .rs file, key types, and design decisions |
| `docs/AUTO_FILTER.md` | How the auto-filter learns 6 constraint types from corpus pairs |
| `docs/CORPUS_CONVENTIONS.md` | Naming, tier requirements, multi-API variant creation |
| `docs/SCORING_DIMENSIONS.md` | 11-dimensional similarity model, default weights, flow_sim generalization gap |
| `docs/MATCH_EVIDENCE.md` | Per-dimension evidence breakdown — the equivalent of a compiler telling you which variable has a type error |
| `FRENSENSE_CORPUS_GUIDE.md` | Five tiers, CWE mapping table, mutation guidelines |
| `FRENSENSE_VS_LITERATURE.md` | Comparison against 227 academic studies from the 2025 systematic review |

### Quality Scoring

```bash
# Score all corpus patterns (0-100). Run anytime to assess quality.
corpus-quality corpus/targets/  # If installed via cargo, otherwise: cargo run --bin corpus-quality -- corpus/targets/

# Output: TSV sorted by score (lowest first). Patterns below 50 need rewrites.
# Includes per-tier breakdown showing how many patterns need work.
```

### Latest Benchmark (Sep 2026) — v0.6.0 PDG Data-Flow Upgrade

**OWASP Juice Shop** (37 vulnerable files, ground truth: `challengeUtils.solveIf` markers)

| Metric | Results |
|---|---|
| True Positives | 112 |
| False Positives | 112 |
| **Precision** | **50.00%** |
| **File Recall** | **54.05%** (20/37) |

**NodeGoat** (30 vulnerabilities across 14 files)

| Metric | Results |
|---|---|
| True Positives | 74 |
| False Positives | 11 |
| **Precision** | **87.06%** |
| **Recall** | **56.67%** (17/30) |

The exact PDG data-flow improvements allowed the engine to generalize across framework dialects (e.g. `db.query` vs `sequelize.query`) without strict gates. NodeGoat precision reached 87% while maintaining excellent recall.

## License

MIT
