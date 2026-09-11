# Crate: `frensense-runtime` — Dynamic Runtime Instrumentation

**Path:** `frensense-runtime/src/`  
**Role:** Standalone sidecar process. Instruments a running application to confirm or refute static findings dynamically.

---

## Purpose

Static analysis can only tell you that tainted data *could* reach a sink — it cannot tell you that it *does* reach a sink with a real HTTP request. The runtime crate bridges this gap: it runs alongside the target application, observes actual executions, and correlates them with static findings.

This is the Frensense answer to the broader question: "Is this a real vulnerability or a false positive in my deployment?"

---

## Architecture

```
Static Analysis Engine                 Runtime Sidecar
        │                                     │
        │  findings.json                      │
        └───────────────────────────────────► │
                                              │
                    Target Application        │
                    (Express / Hono / Axum)   │
                           │                  │
                           │  HTTP traffic    │
                           ◄──────────────────┤  route_extractor.rs
                           │                  │
                           │  trace events    │
                           └─────────────────►│  tracer.rs
                                              │
                                         scheduler.rs
                                              │
                                         oracle.rs
                                              │
                                         canary.rs
                                              │
                                      advisory.rs → output
```

---

## Module Reference

### `main.rs` — Sidecar Entry Point

Starts the runtime sidecar as a separate process. Accepts configuration via `config.rs` (port, target URL, probe intervals, finding file path).

### `session.rs` — Session Management

Manages the analysis session lifecycle:
- `Session::new()` — initialize a runtime analysis session.
- `Session::attach(target_url)` — connect to the running target application.
- `Session::run()` — main event loop: collect traces, schedule probes, report findings.
- `Session::detach()` — clean shutdown without disrupting the target.

### `route_extractor.rs` — HTTP Route Map Extraction

Queries the running target to extract its route map. Supports:
- **Express.js:** Queries the `app._router.stack` internal structure via a debug endpoint.
- **Fastify:** Uses `fastify.printRoutes()` output.
- **Hono:** Route inspection via the framework's internal route registry.
- **Axum:** Route enumeration via the `axum::Router` debug format.

The extracted route map (`HashMap<Method, Vec<PathPattern>>`) is used to generate targeted probe requests.

### `tracer.rs` — Execution Trace Collection

Collects execution traces from the target:
- **Node.js:** Uses `--inspect` protocol (V8 debugger) to capture function call stacks.
- **Rust/Axum:** Uses tracing hooks via `tracing-subscriber` integration.
- Traces are recorded as `TraceEvent { function_name, args_snapshot, timestamp }` sequences.

### `scheduler.rs` — Probe Scheduling

Schedules when and how often probes are sent:
- `LinearScheduler` — sends probes at fixed intervals.
- `AdaptiveScheduler` — increases probe frequency for findings with high static confidence.
- `BurstScheduler` — sends a burst of probes to test rate limiting.

### `oracle.rs` — Ground-Truth Oracle

After sending a probe, the oracle determines whether the vulnerability was triggered:
- Checks HTTP response codes and bodies for error signatures.
- Inspects trace events for sink function invocations with tainted arguments.
- Compares expected vs. actual behavior from `[frensense]` block's `exploit_scenario` field.

### `canary.rs` — Canary Payload Injection

For each finding marked with `runtime_probe`, generates a canary payload:
- **SSRF:** Sends a request URL pointing to a controlled canary server; checks if the server receives an outbound request.
- **SQLi:** Sends time-based blind payloads; measures response latency.
- **CMDI:** Sends payloads that write to a canary file; checks if file exists.
- **Open Redirect:** Sends a redirect to a controlled URL; follows redirects.

### `advisory.rs` — Runtime Finding Formatter

Converts confirmed runtime findings into `Advisory` structs with `confidence = 0.99` (confirmed by dynamic execution). These are emitted alongside static findings in the final report.

### `probes/` — Probe Definitions

Individual probe implementations for each vulnerability class:

| Probe | Technique |
|---|---|
| `ssrf_probe` | DNS/HTTP canary server callback |
| `sqli_probe` | Time-based blind, error-based, UNION-based |
| `cmdi_probe` | `sleep`/`ping` timing, file write canary |
| `path_traversal_probe` | `/etc/passwd` content detection |
| `open_redirect_probe` | Redirect chain following |
| `xss_probe` | Reflected payload detection in response |

### `adapters/` — Language Runtime Adapters

Language-specific hooks for attaching to running processes:

| Adapter | Mechanism |
|---|---|
| `node_adapter` | V8 Inspector Protocol, `--require` hooks |
| `rust_adapter` | `tracing` crate subscriber, `tokio-console` protocol |
| `go_adapter` | `pprof` endpoint, Go runtime trace |

---

## CS Theory

| Concept | Application |
|---|---|
| **Dynamic analysis** | Runtime observation of actual program execution |
| **Concolic testing** | Concrete execution + symbolic canary payloads to test reachability |
| **Runtime verification** | Check properties (no tainted data reaches sink) against actual execution |
| **Fuzzing probes** | Targeted input generation to trigger specific vulnerability classes |
| **Fault injection** | Canary payloads as fault-injection to confirm exploitability |

---

## Relationship to Static Analysis

The runtime crate does NOT replace static analysis — it complements it:

- Static analysis has **high recall** (finds all potential paths) but moderate precision.
- Runtime probing has **perfect precision** for confirmed findings (if the probe triggers, it's real) but zero recall for unexplored paths.

Together they form a **confidence escalation pipeline**: static analysis identifies candidates, runtime probing confirms the highest-confidence ones.
