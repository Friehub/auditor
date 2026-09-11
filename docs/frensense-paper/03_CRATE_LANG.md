# Crate: `frensense-lang` — Language Abstraction Layer

**Path:** `frensense-lang/src/`  
**Role:** Leaf crate. Defines the single `LanguageSpec` trait that every engine subsystem calls instead of containing hardcoded language-specific `match` arms.

---

## Purpose

Previous versions of the engine had nine independent hardcoding sites where each subsystem (fingerprint, CFG, def-use, flow-fingerprint, import resolver, etc.) contained its own `match kind { "call_expression" | "method_call" | ... }` arms for each language. Adding a new language required patching all nine sites.

`frensense-lang` consolidates this into one trait with one implementation per language. Any engine subsystem that needs a language-specific fact calls `spec.classify(node_kind)` or `spec.is_sink(call_text)` — never string literals.

---

## `NodeRole` Enum

The `NodeRole` enum encodes what role a tree-sitter node plays in the program. Variants carry the **field names** needed to walk child nodes, so callers never need a second lookup. All `*_field` values are `&'static str` — they come from tree-sitter grammar constants and never allocate.

```rust
pub enum NodeRole {
    // Definitions
    Function {
        is_method:    bool,
        name_field:   Option<&'static str>,  // None for arrow functions, closures
        params_field: &'static str,
        body_field:   &'static str,
    },

    // Assignments / declarations
    Declaration { name_field: &'static str, value_field: &'static str },
    Assignment  { lhs_field: &'static str,  rhs_field: &'static str },

    // Calls
    Call         { callee_field: &'static str, args_field: &'static str },
    MemberAccess { object_field: &'static str, property_field: &'static str },

    // Control flow
    Branch,  // if / switch / ternary / match-arm
    Loop,    // for / while / do / loop
    Return,
    Try,
    Catch,
    Finally,
    Throw,

    // Special patterns
    ErrorGuard,        // Go: if err != nil
    ContextManager,    // Python: with expr as var
    ErrorPropagation,  // Rust: ?
    Await,

    // Structural
    Block,
    Import,
    Export,
    Identifier,
    Literal,
    Other,
}
```

---

## `LanguageSpec` Trait

```rust
pub trait LanguageSpec: Send + Sync {
    /// Map a tree-sitter node kind string to a NodeRole.
    fn classify(&self, node_kind: &str) -> NodeRole;

    /// Classify a parameter name/type as a taint source, if applicable.
    fn classify_param_taint(
        &self,
        name: Option<&str>,
        ty:   Option<&str>,
    ) -> Option<TaintOrigin>;

    /// Is this call expression text a dangerous sink?
    fn is_sink(&self, call_text: &str) -> bool;

    /// Tree-sitter node kinds that represent function definitions.
    fn function_node_kinds(&self) -> &[&str];

    /// Tree-sitter node kinds that represent import statements.
    fn import_node_kinds(&self) -> &[&str];

    /// Tree-sitter node kind for the program root.
    fn program_node_kind(&self) -> &str;

    // ... additional optional methods with default no-op implementations
}
```

---

## `TaintOrigin` Enum

```rust
pub enum TaintOrigin {
    UserInput,        // req.body, form data, URL params
    EnvVariable,      // process.env, os.Getenv
    FileSystem,       // file reads
    Database,         // DB query results (secondary source)
    ExternalService,  // HTTP responses from external calls
}
```

This is the language-facing type. The engine crate maps it to its own `data_flow::TaintOrigin` which adds `Network` and `Custom(String)`.

---

## `spec_for_ext()` Factory

```rust
pub fn spec_for_ext(ext: &str) -> Option<&'static dyn LanguageSpec>
```

Dispatches by file extension to the appropriate compiled-in spec:

| Extension | Spec |
|---|---|
| `ts`, `tsx` | `TypeScriptSpec` |
| `js`, `jsx`, `mjs`, `cjs` | `JavaScriptSpec` |
| `rs` | `RustSpec` |
| `go` | `GoSpec` |
| `py`, `pyi` | `PythonSpec` |
| others | `None` |

---

## Per-Language Implementations (in `providers/`)

Each implementation provides the grammar constants for that language's tree-sitter parse tree:

### TypeScript/JavaScript

```
function_declaration       → Function { name_field: "name", params: "parameters", body: "body" }
arrow_function             → Function { name_field: None,   params: "parameters", body: "body" }
call_expression            → Call { callee: "function",     args: "arguments" }
member_expression          → MemberAccess { object: "object", property: "property" }
if_statement               → Branch
for_statement              → Loop
await_expression           → Await
import_statement           → Import
```

### Rust

```
function_item              → Function { name: "name", params: "parameters", body: "body" }
call_expression            → Call { callee: "function", args: "arguments" }
field_expression           → MemberAccess
if_expression              → Branch
loop_expression            → Loop
?  (try operator)          → ErrorPropagation
await_expression           → Await
use_declaration            → Import
```

### Go

```
function_declaration       → Function { name: "name", params: "parameters", body: "body" }
method_declaration         → Function { is_method: true, ... }
call_expression            → Call
selector_expression        → MemberAccess
if_statement               → Branch (with ErrorGuard detection for "err != nil")
for_statement              → Loop
import_declaration         → Import
```

---

## CS Theory

| Concept | Application |
|---|---|
| **Strategy Pattern** | `LanguageSpec` is the strategy interface; each language is a concrete strategy |
| **Polymorphic dispatch** | `dyn LanguageSpec` — runtime dispatch over language implementations |
| **Grammar abstraction** | `NodeRole` is the abstract grammar; tree-sitter node kinds are the concrete grammar |
| **Open/Closed Principle** | Adding a new language only requires a new `LanguageSpec` impl — no existing code changes |

---

## Design Decisions

**Why one big trait rather than many small ones?**  
Previous analysis showed nine separate hardcoding sites. Splitting the fix across nine small traits creates nine places a new language author can forget to implement. A single trait with good defaults makes the "forgot to implement" case a compile error, not a silent empty result.

**Why `&'static dyn LanguageSpec` and not `Box<dyn LanguageSpec>`?**  
Language specs are stateless singletons — all their data is in `&'static str` grammar constants. Using static references avoids heap allocation on the hot path (every fingerprint extraction call goes through `spec_for_ext`).
