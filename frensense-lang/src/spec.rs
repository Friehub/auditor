// SPDX-License-Identifier: MIT
//!
//! The [`LanguageSpec`] trait is the single contract every language must
//! satisfy. All engine subsystems (fingerprint, CFG, def-use, flow-fingerprint,
//! import resolver, semantic provider) call *this* trait instead of containing
//! their own hardcoded `match kind { "call_expression" | … }` arms.
//!
//! # Why one trait, not many?
//!
//! Previous analysis showed nine separate hardcoding sites. Splitting the fix
//! across nine small traits creates nine places a new language author can
//! forget to implement one. A single trait with good defaults makes the
//! "forgot to implement" case a compile error, not a silent empty result.

use tree_sitter::Node;

// ── Supporting types ─────────────────────────────────────────────────────────

/// What role does a tree-sitter node play in the language?
///
/// Variants carry the **field names** needed to walk child nodes so callers
/// never need a second lookup.  All `*_field` values are `'static str` — they
/// come from tree-sitter grammar constants and never allocate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRole {
    // ── Definitions ──────────────────────────────────────────────────────
    /// A named or anonymous function / method / closure.
    Function {
        /// True when the grammar distinguishes methods from top-level functions
        /// (TS `method_definition`, Go `method_declaration`).
        is_method: bool,
        /// Field holding the function's name identifier, if any.
        /// `None` for arrow functions, lambdas, anonymous closures.
        name_field: Option<&'static str>,
        /// Field holding the parameter list node.
        params_field: &'static str,
        /// Field holding the body block node.
        body_field: &'static str,
    },

    // ── Assignments / declarations ────────────────────────────────────────
    /// A variable declaration with an initializer.
    /// `let x = expr` (JS/Rust), `x := expr` (Go).
    Declaration {
        name_field: &'static str,
        value_field: &'static str,
    },
    /// A mutation of an existing binding.
    /// `x = expr` (all languages), `x += expr`.
    Assignment {
        lhs_field: &'static str,
        rhs_field: &'static str,
    },

    // ── Calls ─────────────────────────────────────────────────────────────
    /// Any function / method invocation.
    Call {
        callee_field: &'static str,
        args_field: &'static str,
    },
    /// Member / field access producing a value (not a call).
    /// `obj.field`, `obj->field`, `obj.attribute`.
    MemberAccess {
        object_field: &'static str,
        property_field: &'static str,
    },

    // ── Control flow ──────────────────────────────────────────────────────
    Branch,  // if / switch / ternary / match-arm
    Loop,    // for / while / do / loop
    Return,  // return statement / expression
    Try,     // try { … }
    Catch,   // catch / except clause
    Finally, // finally clause
    Throw,   // throw / raise

    // ── Special language patterns ─────────────────────────────────────────
    /// Go: `if err != nil { return … }` — structurally a Branch but semantically
    /// an error propagation guard; the engine needs to detect it for auth-guard
    /// dominator analysis.
    ErrorGuard,
    /// Python: `with expr as var:` — a context-manager entry; the callee
    /// may be a path/file sink.
    ContextManager,
    /// Rust: the `?` postfix operator — propagates errors, terminates the
    /// current scope if the value is `Err`.
    ErrorPropagation,
    /// Rust async block, JS/TS `await`, Python `await`.
    Await,

    // ── Structural ────────────────────────────────────────────────────────
    Block,      // { … } / indented block
    Import,     // import / use / require
    Export,     // export (JS/TS only)
    Identifier, // bare name reference
    Literal,    // string / number / bool literal

    /// Anything the engine does not need to inspect.
    Other,
}

/// Sanitizer strength: what kind of injection does this call defeat?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SanitizerKind {
    /// Completely removes taint (e.g. numeric coercion: `int(user_input)`).
    Full,
    /// Defeats HTML/XSS injection only.
    HtmlEscape,
    /// Defeats URL-based attacks only.
    UrlEncode,
    /// Parameterised query — defeats SQL injection only.
    SqlParameterize,
    /// Path canonicalization — defeats path traversal only.
    PathNormalize,
}

/// Broad category for what a package is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackageCategory {
    HttpFramework,
    SqlDatabase,
    NoSqlDatabase,
    CommandExecution,
    FileSystem,
    HttpClient,      // SSRF risk
    TemplateEngine,  // SSTI / XSS
    Deserialization, // unsafe deserialize
    Crypto,
    Logging,
    Testing,
}

/// Broad origin of tainted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintOrigin {
    UserInput,       // HTTP request body/query/path/header
    EnvVariable,     // process.env / os.environ / std::env
    FileSystem,      // file read whose path came from user
    Database,        // query result that may contain injection
    ExternalService, // IPC / downstream API response
}

/// A propagator rule describes how taint flows through a specific call.
///
/// Example: `fmt.Sprintf` in Go — the format string is not tainted, but
/// if *any argument* is tainted the return value is tainted.
#[derive(Debug, Clone)]
pub struct PropagatorRule {
    /// Short call name or method name, e.g. `"Sprintf"`, `"format"`, `"join"`.
    /// Matched against the last segment of a member chain.
    pub call: &'static str,
    /// Argument index that carries taint into the return (0-based).
    /// `None` means *any* argument taints the return.
    pub tainted_arg: Option<usize>,
    /// If `true`, a tainted receiver taints the return value.
    pub tainted_receiver: bool,
}

/// A parsed import as extracted by [`LanguageSpec::extract_imports`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The local binding name, e.g. `"cp"`, `"exec"`, `"Flask"`.
    pub local_name: String,
    /// The source package / module path, e.g. `"child_process"`, `"flask"`.
    pub package: String,
    /// The specific symbol imported, if the language supports named imports.
    /// e.g. `from flask import Flask` → `symbol = Some("Flask")`.
    pub symbol: Option<String>,
}

// ── The trait ─────────────────────────────────────────────────────────────────

/// Everything the frensense engine needs to know about one source language.
///
/// Implement this once per language.  The engine never matches raw node-kind
/// strings anywhere else.
///
/// # Object safety
///
/// The trait is object-safe: it can be stored as `Arc<dyn LanguageSpec>` in
/// the [`LanguageRegistry`](crate::registry::LanguageRegistry).
pub trait LanguageSpec: Send + Sync + 'static {
    // ── Identity ─────────────────────────────────────────────────────────

    /// Canonical short name used in fingerprints and the FRC bundle.
    fn name(&self) -> &'static str;

    /// File extensions handled by this spec (lowercase, no dot).
    fn extensions(&self) -> &'static [&'static str];

    /// The tree-sitter `Language` object for parsing.
    fn tree_sitter_language(&self) -> tree_sitter::Language;

    // ── Node classification ───────────────────────────────────────────────

    /// Classify a tree-sitter node kind into a [`NodeRole`].
    ///
    /// This is the single hot-path entry point for all engine subsystems.
    /// The returned variant carries the field names needed by the caller so
    /// no second lookup is required.
    ///
    /// ```rust
    /// match spec.classify(node.kind()) {
    ///     NodeRole::Call { callee_field, args_field } => {
    ///         let callee = node.child_by_field_name(callee_field);
    ///         // …
    ///     }
    ///     NodeRole::Assignment { lhs_field, rhs_field } => { /* … */ }
    ///     _ => {}
    /// }
    /// ```
    fn classify(&self, kind: &str) -> NodeRole;

    /// Returns `true` if this node is the entry node for a function definition.
    ///
    /// Convenience wrapper around [`classify`](Self::classify); the default
    /// implementation delegates.  Override only when a language has edge-cases
    /// (e.g. Python `decorated_definition` which wraps the real
    /// `function_definition`).
    fn is_function_node(&self, kind: &str) -> bool {
        matches!(self.classify(kind), NodeRole::Function { .. })
    }

    // ── Special structural patterns ───────────────────────────────────────

    /// Returns `true` when this node is a Go-style error guard:
    /// `if err != nil { return … }`.
    ///
    /// The default always returns `false`.  Override in the Go provider.
    fn is_error_guard<'tree>(&self, _node: Node<'tree>, _source: &str) -> bool {
        false
    }

    /// For Python `with_statement` nodes, return the text of the call inside
    /// the `as` clause if it looks like a file/resource sink.
    ///
    /// Returns `None` for all languages that don't have context managers.
    fn context_manager_call<'s>(&self, _node: Node<'_>, _source: &'s str) -> Option<&'s str> {
        None
    }

    // ── Region wrapping ───────────────────────────────────────────────────

    /// Wrap a snippet of source code so it can be re-parsed as a valid
    /// function body.  Used by region chunking in the fingerprinter.
    fn wrap_region(&self, code: &str) -> String;

    // ── Import extraction ─────────────────────────────────────────────────

    /// Tree-sitter node kinds that represent import declarations.
    fn import_node_kinds(&self) -> &'static [&'static str];

    /// Walk `root` and return all imports found in the file.
    ///
    /// The engine calls this once per file; the result is stored in the
    /// `ImportMap` and used by the semantic provider.
    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import>;

    // ── Tree-sitter queries ───────────────────────────────────────────────

    /// A tree-sitter query that captures symbol definitions.
    /// Capture names: `@name` (identifier), optionally `@kind`.
    /// Used to build the per-file symbol table.
    fn symbol_query(&self) -> Option<&'static str> {
        None
    }

    /// A tree-sitter query that captures call edges for the call graph.
    /// Capture names: `@caller`, `@call`.
    fn call_query(&self) -> Option<&'static str> {
        None
    }

    // ── Framework / semantic knowledge ────────────────────────────────────

    /// Map an import package path to its broad category.
    ///
    /// e.g. `"database/sql"` → `Some(PackageCategory::SqlDatabase)`
    ///
    /// Used by the semantic provider to classify sinks and sources without
    /// knowing every individual method name in every package.
    fn package_category(&self, package: &str) -> Option<PackageCategory>;

    /// Is this function parameter a taint source?
    ///
    /// Called with both the name (`"r"`) and the raw type annotation text
    /// (`"*http.Request"`).  Either may be `None`.
    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin>;

    /// Is this decorator / attribute name an HTTP route decorator?
    ///
    /// e.g. Python `@app.route`, Rust `#[get("/")]`, NestJS `@Get("/")`.
    fn is_http_route_decorator(&self, decorator_name: &str) -> bool {
        let _ = decorator_name;
        false
    }

    /// Names of function parameters that conventionally carry HTTP request data.
    ///
    /// Used as a fallback when no type annotation is available.
    fn request_param_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// Known sink function names for this language.
    ///
    /// Returns `(call_name, sink_description)` pairs.  The sink_description is
    /// a short label used in fingerprint hashing, not for display.
    fn known_sink_names(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// Known taint source accessor patterns.
    ///
    /// e.g. `"req.body"`, `"request.args"`, `"r.URL.Query"`.
    fn known_source_patterns(&self) -> &'static [&'static str] {
        &[]
    }

    // ── Taint propagation ─────────────────────────────────────────────────

    /// Propagator rules for this language's standard library / builtins.
    ///
    /// The engine uses these to decide whether the return value of a call is
    /// tainted when one of its arguments is.
    fn propagator_rules(&self) -> &'static [PropagatorRule];

    /// Is this call a sanitizer?  Returns the strength if so.
    fn classify_sanitizer(&self, call_name: &str) -> Option<SanitizerKind>;

    // ── Context hints ─────────────────────────────────────────────────────

    /// Text strings whose presence in a source file suggests an HTTP handler
    /// context.  Used by the text-based context detector as a fast first pass.
    fn route_context_hints(&self) -> &'static [&'static str] {
        &[]
    }

    /// Text strings indicating a test / spec file.
    fn test_context_hints(&self) -> &'static [&'static str] {
        &[]
    }

    // ── Engine knowledge not yet covered by spec ─────────────────────────────

    /// HTTP response method names for this language.
    fn response_method_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// Database API method names.
    fn db_api_method_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// Shell execution API names.
    fn shell_api_method_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// Route registration call patterns.
    fn route_registration_patterns(&self) -> &'static [&'static str] {
        &[]
    }
}

// ── Helper: extract the last segment of a dotted call ────────────────────────

/// `"fmt.Sprintf"` → `"Sprintf"`, `"exec"` → `"exec"`.
#[inline]
pub fn call_last_segment(call: &str) -> &str {
    call.rsplit('.').next().unwrap_or(call)
}

// ── Helper: node text ─────────────────────────────────────────────────────────

/// Extract the UTF-8 text for a node from the source slice.
#[inline]
pub fn node_text<'s>(node: Node<'_>, source: &'s str) -> &'s str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}
