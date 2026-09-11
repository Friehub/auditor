# Crate: `frensense-providers` — Compiler Backends

**Path:** `frensense-providers/src/`  
**Role:** Optional crate. Provides exact semantic resolution by mounting real language compilers, replacing heuristic name-matching with type-resolved answers.

Activated via feature flags: `--features oxc` for JS/TS, `--features rust-hir` for Rust.

---

## The Precision Spectrum

Frensense has three levels of semantic resolution for source/sink classification:

| Provider | Cost | Accuracy | When to Use |
|---|---|---|---|
| `ImportMapProvider` | ~0 ms/file | Heuristic (good for common patterns) | Default mode |
| `OxcProvider` | ~50 ms/file | Exact JS/TS type resolution | `--use-compiler` on TS/JS projects |
| `RustHirProvider` | ~200 ms/file | Exact Rust trait + type resolution | `--use-compiler` on Rust projects |

All three implement the same `SemanticProvider` trait defined in `frensense-engine/src/semantic.rs`.

---

## `SemanticProvider` Trait

```rust
pub trait SemanticProvider: Send + Sync {
    /// Is this parameter a taint source, and what kind?
    fn classify_param(
        &self,
        name: &str,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin>;

    /// Is this call expression a dangerous sink?
    fn classify_sink(
        &self,
        call_text: &str,
        resolved_module: Option<&str>,
    ) -> Option<SinkCategory>;

    /// Is this function an HTTP handler?
    fn is_http_handler(
        &self,
        fp: &FunctionFingerprint,
        type_context: &TypeContext,
    ) -> bool;

    /// Does the current file import this package?
    fn file_imports(&self, package: &str) -> bool;

    /// Resolve a local name to its source package.
    fn resolve_name(&self, name: &str) -> Option<String>;

    /// All known sink function names for this language.
    fn known_sinks(&self) -> Vec<String>;
}
```

---

## Module: `oxc_provider.rs` — OXC TypeScript/JavaScript Provider

**File size:** 37 KB — the largest single source file in the workspace.

### What OXC Gives Us

The Oxc (JavaScript/TypeScript compiler toolchain in Rust) provides what tree-sitter heuristics cannot:

- **Real module resolution:** bare imports, scoped packages (`@org/pkg`), `tsconfig.json` path aliases (`@app/*`), `package.json` `exports`/`main` fields, dynamic `import()`.
- **Binding table:** `const db = new Pool()` → `db` is bound to `pg.Pool`.
- **Barrel re-export following:** `@hono/node-server` re-exports `hono` → still classified correctly up to depth 4.
- **Cross-file type propagation** (limited, within the file).

### `OxcSymbolTable`

The core output of parsing a file with Oxc:

```rust
pub struct OxcSymbolTable {
    pub bindings: FxHashMap<String, ResolvedModule>,  // local name → package
    pub imports:  FxHashMap<String, String>,           // local alias → package path
    pub call_sites: Vec<OxcCallSite>,                  // all call expressions with resolved module
}
```

### Module Resolution Algorithm

```
1. Parse file with Oxc (oxc_parser::Parser)
2. Walk import/require declarations via oxc_ast_visit::Visit
3. For each import specifier:
   a. Resolve the module specifier via oxc_resolver::Resolver
      - Checks node_modules/ in parent directories
      - Follows package.json exports/main fields
      - Applies tsconfig.json path mappings
   b. Follow up to MAX_BARREL_DEPTH (4) re-export chains
   c. Extract the root package name from the resolved path
4. Build OxcSymbolTable: local_name → resolved_package
```

Extension resolution order:
```
.ts → .tsx → .mts → .cts → .js → .jsx → .mjs → .cjs → .json → .d.ts → .node
```

### Source/Sink Classification

With the `OxcSymbolTable` available:

- `classify_param(name, type)`: if the type annotation resolves to `express.Request`, `hono.Context`, `fastify.FastifyRequest`, etc. → `TaintOrigin::UserInput`.
- `classify_sink(call, module)`: if the resolved module is `node:child_process` → `SinkCategory::CommandExecution`; if `pg`, `mysql2`, `sequelize` → `SinkCategory::SqlQuery`; etc.

The `PACKAGE_SINK_CATEGORIES` table maps package names to `SinkCategory`:

```
"node:child_process", "child_process"  → CommandExecution
"pg", "mysql2", "sequelize", "knex"    → SqlQuery
"node:fs", "fs-extra", "fs/promises"   → FileSystem
"axios", "node-fetch", "got", "ky"     → NetworkFetch
"nodemailer", "sendgrid"               → EmailSink
...
```

### `HTTP_FRAMEWORK_PACKAGES`

```rust
pub const HTTP_FRAMEWORK_PACKAGES: &[&str] = &[
    "express", "fastify", "hono", "koa", "@nestjs/common",
    "next", "nuxt", "@remix-run/react", "astro",
    // ... 20+ frameworks
];
```

A function is classified as an HTTP handler if any of its parameters resolves to a type from one of these packages.

### CS Theory

| Concept | Application |
|---|---|
| **Module resolution algorithm** | Node.js module resolution spec + tsconfig path mapping |
| **Barrel/re-export following** | Bounded-depth transitive closure over re-export edges |
| **Type-directed taint classification** | Type annotations as taint labels (information-flow types) |
| **Abstract interpretation** | Package names as abstract values approximating runtime types |

---

## Module: `rust_hir_provider.rs` — Rust HIR Provider

**File size:** 23 KB.

Uses `rust-analyzer`'s High-Level Intermediate Representation (HIR) to answer semantic questions about Rust code with full type resolution.

### What HIR Gives Us

- Trait resolution: `impl Deref for MyReq<T>` — the provider knows `MyReq` dereferences to `axum::extract::Request`.
- Macro expansion: `#[derive(Deserialize)]` on a struct → the struct's fields are taint sources when received via `Json<MyStruct>`.
- Lifetime and borrow checker integration: can identify when a tainted reference escapes a function scope.

### Architecture

```
rustc HIR analysis (background rust-analyzer process)
       ↓
RustHirProvider.classify_param(name, type_annotation)
  → query HIR for the fully qualified type of the parameter
  → check against known source type patterns (axum::extract::Path<T>, etc.)
  → return Option<TaintOrigin>
```

The provider communicates with rust-analyzer via its LSP-style API, spawning it as a subprocess when `--use-compiler` is active.

### Known Limitation

This provider is currently a stub in the codebase — the architecture is defined and the trait implementation is wired up, but the HIR query logic is incomplete. Rust analysis falls back to `ImportMapProvider` in practice.

---

## Design: Why Separate Crate?

`frensense-providers` is intentionally a separate crate rather than modules inside `frensense-engine` because:

1. **Heavy dependencies:** Oxc brings in `oxc_allocator`, `oxc_ast`, `oxc_parser`, `oxc_resolver`, `oxc_span`, `oxc_syntax` — a significant compile-time cost. Users who don't use `--use-compiler` should not pay for this.
2. **Optional compilation:** The `oxc` and `rust-hir` features are off by default. The default binary compiles without Oxc or rust-analyzer.
3. **Version isolation:** Oxc evolves rapidly. Isolating it prevents Oxc API changes from cascading into the engine crate.
