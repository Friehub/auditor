#![allow(clippy::all)]
#![allow(dead_code, unreachable_patterns, unreachable_code)]
// SPDX-License-Identifier: MIT
//! # frensense-lang
//!
//! Per-language AST knowledge for the frensense static analysis engine.
//!
//! ## The Problem This Crate Solves
//!
//! Before this crate, frensense had language-specific knowledge scattered
//! across nine source files as raw tree-sitter node-kind strings:
//!
//! ```text
//! fingerprint.rs:997   matches!(kind, "function_item" | "function_declaration" | ...)
//! flow_fingerprint.rs  kind == "variable_declarator" || kind == "assignment_expression"
//! cfg/mod.rs           "if_statement" | "try_statement" | "catch_clause" | ...
//! cfg/def_use.rs       "let_declaration" | "call_expression" | "member_expression"
//! parser.rs            match ext { "go" => None, ... }   ← no call_query for Go
//! import_resolver.rs   "import_statement" only (no Go/Python/Rust imports)
//! route_registry.rs    Express-only route patterns
//! function_role.rs     JS-centric parameter name lists
//! context/mod.rs       Text strings for JS/TS context detection
//! ```
//!
//! The result: Python produced **zero fingerprints** (function_definition not in
//! the match), Go methods were silently skipped (method_declaration not in the
//! match), and data-flow taint tracking silently produced empty paths for both
//! (wrong member-access and call node kinds).
//!
//! ## The Fix: One Call Per Decision
//!
//! Every engine subsystem now calls the spec once:
//!
//! ```rust
//! use frensense_lang::registry::spec_for_ext;
//! use frensense_lang::spec::NodeRole;
//!
//! fn process_node(node: tree_sitter::Node, source: &str, ext: &str) {
//!     let spec = spec_for_ext(ext).expect("unsupported extension");
//!
//!     match spec.classify(node.kind()) {
//!         NodeRole::Function { name_field, params_field, body_field, .. } => {
//!             // Works for Go method_declaration, Python function_definition,
//!             // Rust function_item, JS arrow_function — all correct.
//!             let name = name_field.and_then(|f| node.child_by_field_name(f));
//!         }
//!         NodeRole::Declaration { name_field, value_field } => {
//!             // Works for `x := expr` (Go), `x = expr` (Python),
//!             // `let x = expr` (Rust), `const x = expr` (JS).
//!         }
//!         NodeRole::Call { callee_field, args_field } => {
//!             // Covers `call_expression` (JS/Go/Rust) AND `call` (Python).
//!         }
//!         NodeRole::MemberAccess { object_field, property_field } => {
//!             // Covers `member_expression` (JS), `selector_expression` (Go),
//!             // `attribute` (Python), `field_expression` (Rust).
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! ## Migration Guide for Each Engine Subsystem
//!
//! ### 1. `fingerprint.rs` — function detection
//!
//! **Before:**
//! ```rust
//! if matches!(kind, "function_item" | "function_declaration" | "method_definition" | "arrow_function")
//! ```
//! **After:**
//! ```rust
//! if spec.is_function_node(kind) { … }
//! // or for the full match with field names:
//! if let NodeRole::Function { name_field, params_field, body_field, .. } = spec.classify(kind) { … }
//! ```
//!
//! **Region wrapping:**
//! **Before:**
//! ```rust
//! let code = match lang {
//!     Language::Rust   => format!("fn _region() {{\n{}\n}}", src),
//!     Language::Python => { let indented = …; format!("def _region():\n{}", indented) }
//!     _                => format!("function _region() {{\n{}\n}}", src),
//! };
//! ```
//! **After:**
//! ```rust
//! let code = spec.wrap_region(src);
//! ```
//!
//! ### 2. `corpus/flow_fingerprint.rs` — taint propagation
//!
//! **Before:**
//! ```rust
//! if kind == "variable_declarator" || kind == "assignment_expression" {
//!     let name  = node.child_by_field_name("name").or_else(|| node.child_by_field_name("left"));
//!     let value = node.child_by_field_name("value").or_else(|| node.child_by_field_name("right"));
//! }
//! // …
//! if node.kind() == "call_expression" { … }
//! // …
//! "member_expression" => { … }
//! ```
//! **After:**
//! ```rust
//! match spec.classify(node.kind()) {
//!     NodeRole::Declaration { name_field, value_field }
//!     | NodeRole::Assignment { lhs_field: name_field, rhs_field: value_field } => {
//!         let name  = node.child_by_field_name(name_field);
//!         let value = node.child_by_field_name(value_field);
//!     }
//!     NodeRole::Call { callee_field, args_field } => { … }
//!     NodeRole::MemberAccess { object_field, property_field } => { … }
//!     NodeRole::ContextManager => {
//!         // Python `with open(path) as f:` — new, was invisible before
//!         if let Some(path_text) = spec.context_manager_call(node, source) { … }
//!     }
//!     _ => {}
//! }
//! ```
//!
//! ### 3. `cfg/mod.rs` — CFG construction
//!
//! **Before:**
//! ```rust
//! match kind {
//!     "if_statement" | "if_expression" | "ternary_expression" => { … }
//!     "try_statement" => { … }
//!     "catch_clause" => { … }   // wrong for Python (except_clause)
//!     "finally_clause" => { … }
//!     _ => {}
//! }
//! ```
//! **After:**
//! ```rust
//! match spec.classify(node.kind()) {
//!     NodeRole::Branch          => { /* add branch edges */ }
//!     NodeRole::Loop            => { /* add back-edge */ }
//!     NodeRole::Try             => { /* add exception edge */ }
//!     NodeRole::Catch           => { /* exception handler entry */ }
//!     NodeRole::Finally         => { /* finally block */ }
//!     NodeRole::ErrorGuard      => {
//!         // Go `if err != nil { return }` — confirmed via spec.is_error_guard()
//!         if spec.is_error_guard(node, source) { /* exception-like edge */ }
//!     }
//!     NodeRole::ErrorPropagation => {
//!         // Rust `?` operator — propagates error out of current scope
//!     }
//!     _ => {}
//! }
//! ```
//!
//! ### 4. `cfg/def_use.rs` — def-use chains
//!
//! **Before:**
//! ```rust
//! match kind {
//!     "let_declaration" | "lexical_declaration" | "variable_declaration" => { … }
//!     "assignment_expression" | "assignment" => { … }
//!     "call_expression" => { … }
//! }
//! // extract_ref_names used "member_expression" (wrong for Go/Python/Rust)
//! ```
//! **After:**
//! ```rust
//! match spec.classify(kind) {
//!     NodeRole::Declaration { name_field, value_field } => { … }
//!     NodeRole::Assignment  { lhs_field, rhs_field }   => { … }
//!     NodeRole::Call        { callee_field, args_field }=> { … }
//!     NodeRole::MemberAccess{ object_field, .. }        => {
//!         // Now covers selector_expression (Go), attribute (Python),
//!         // field_expression (Rust) — all were silently skipped before.
//!     }
//!     _ => {}
//! }
//! ```
//!
//! ### 5. `import_resolver.rs` — import extraction
//!
//! **Before:** only `import_statement` (ESM) and `require()` (CJS).
//!
//! **After:**
//! ```rust
//! // Call once per file. Replaces the manual walk in import_resolver.rs.
//! let imports: Vec<Import> = spec.extract_imports(root_node, source);
//! for import in imports {
//!     import_map.bind(import.local_name, import.package);
//! }
//! ```
//! Go `import_declaration`, Python `import_from_statement`, Rust `use_declaration`
//! are all handled by the respective spec's `extract_imports` implementation.
//!
//! ### 6. `parser.rs` — tree-sitter queries
//!
//! **Before:**
//! ```rust
//! pub fn call_query_for_ext(ext: &str) -> Option<&'static str> {
//!     match ext {
//!         "rs" => Some("…"),
//!         "ts" | "tsx" | "js" | "jsx" => Some("…"),
//!         "py" | "pyi" => Some("…"),
//!         "go" => None,   // ← no call graph for Go
//!         _ => None,
//!     }
//! }
//! ```
//! **After:**
//! ```rust
//! let call_query = spec_for_ext(ext).and_then(|s| s.call_query());
//! ```
//! Go now has a full call query; Python's is improved to cover class methods.
//!
//! ### 7. Semantic providers (`semantic.rs`)
//!
//! **Before:** `ImportMapProvider` (heuristic) only worked for JS/TS because
//! the import map was always empty for Go/Python/Rust files.
//!
//! **After:** use `spec.extract_imports()` to build the import map, then
//! `spec.package_category(pkg)` to classify the package:
//! ```rust
//! fn classify_sink(&self, call_text: &str, _resolved: Option<&str>) -> Option<SinkCategory> {
//!     let receiver = call_text.split('.').next()?;
//!     let pkg      = self.import_map.resolve(receiver)?;
//!     match self.spec.package_category(pkg)? {
//!         PackageCategory::SqlDatabase      => Some(SinkCategory::SqlInjection),
//!         PackageCategory::CommandExecution => Some(SinkCategory::CommandInjection),
//!         PackageCategory::HttpClient       => Some(SinkCategory::Ssrf),
//!         PackageCategory::FileSystem       => Some(SinkCategory::PathTraversal),
//!         PackageCategory::TemplateEngine   => Some(SinkCategory::TemplateSsti),
//!         PackageCategory::Deserialization  => Some(SinkCategory::UnsafeDeserialize),
//!         _ => None,
//!     }
//! }
//! ```
//!
//! ### 8. Route detection (`route_registry.rs`, `function_role.rs`, `context/mod.rs`)
//!
//! **Before:** Express-only static arrays.
//!
//! **After:**
//! ```rust
//! // Context detection — replaces ROUTE_ENV_KEYWORDS static array
//! let hints = spec.route_context_hints();
//! let is_route_context = hints.iter().any(|h| file_source.contains(h));
//!
//! // Decorator detection — replaces hardcoded NestJS decorator list
//! let is_route = spec.is_http_route_decorator(decorator_name);
//!
//! // Parameter taint — replaces REQUEST_PARAM_NAMES
//! let origin = spec.classify_param_taint(Some(param_name), type_annotation);
//! ```
//!
//! ### 9. Motif call-name collection (`fingerprint.rs::collect_raw_call_names`)
//!
//! **Before:** only extracted call names from `call_expression` and
//! `member_expression` — Python `call` and Go `selector_expression` were silently
//! skipped, so motif hashes were never computed for those languages.
//!
//! **After:**
//! ```rust
//! match spec.classify(node.kind()) {
//!     NodeRole::Call { callee_field, .. } => {
//!         let callee = node.child_by_field_name(callee_field)?;
//!         // recurse into callee to build "object.method" string
//!     }
//!     NodeRole::MemberAccess { object_field, property_field } => {
//!         let obj  = node.child_by_field_name(object_field)?;
//!         let prop = node.child_by_field_name(property_field)?;
//!         // covers selector_expression (Go), attribute (Python), etc.
//!     }
//!     _ => {}
//! }
//! ```

pub mod providers;
pub mod registry;
pub mod spec;

// Convenient re-exports
pub use registry::{spec_for_ext, spec_for_path, LanguageRegistry};
pub use spec::{
    Import, LanguageSpec, NodeRole, PackageCategory, PropagatorRule, SanitizerKind, TaintOrigin,
};
