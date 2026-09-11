// SPDX-License-Identifier: MIT

//! Semantic knowledge abstraction.
//!
//! The engine asks a [`SemanticProvider`] for semantic facts about the code
//! being analysed instead of scattering hardcoded heuristics across the
//! pipeline (import resolution, function-role classification, source/sink
//! detection). Each provider trades accuracy for cost:
//!
//! 1. [`ImportMapProvider`] — zero new dependencies. Uses the already-built
//!    per-file [`ImportMap`] to answer "which package does this name come from?",
//!    so framework-typed parameters and package-owned receivers are classified
//!    by the import system rather than by guessing from method names. Falls back
//!    to name matching only for unannotated code.
//! 2. `OxcProvider` — exact JavaScript/TypeScript resolution via Oxc (the
//!    `oxc` feature; see [`crate::oxc_provider`]).
//! 3. `RustHirProvider` — exact Rust types via rust-analyzer (stub).
//!
//! The old heuristics are intentionally not deleted yet; they are re-exposed
//! behind the trait so later steps can swap providers without touching every
//! call site.

use std::path::PathBuf;
use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::corpus::source_sink::{CorpusSourceSinkRegistry, SinkCategory};
use crate::data_flow::TaintOrigin;
use crate::fingerprint::FunctionFingerprint;
use crate::import_resolver::ImportMap;

/// A source of semantic knowledge about the code being analysed.
///
/// The engine calls this instead of hardcoded heuristics. Implementations
/// range from fast-but-approximate (name matching) to exact (compiler type
/// resolution).
pub trait SemanticProvider: Send + Sync {
    /// Is this parameter a taint source, and what kind?
    /// Called with both the parameter name AND its type annotation text.
    fn classify_param(&self, name: &str, type_annotation: Option<&str>) -> Option<TaintOrigin>;

    /// Is this call expression a dangerous sink?
    /// `call_text` is the raw call expression text ("exec", "db.query", etc.)
    /// `resolved_module` is the fully-qualified module if known ("node:child_process").
    fn classify_sink(&self, call_text: &str, resolved_module: Option<&str>)
    -> Option<SinkCategory>;

    /// Is this function an HTTP handler?
    /// Called with the fingerprint and any available type information.
    fn is_http_handler(&self, fp: &FunctionFingerprint, type_context: &TypeContext) -> bool;

    /// Does the current file import this package?
    fn file_imports(&self, package: &str) -> bool;

    /// Resolve a local name to its source package.
    fn resolve_name(&self, name: &str) -> Option<String>;

    /// All known sink function names for this language (e.g. "eval", "exec",
    /// "query"). Used to populate the corpus registry's baseline sink list.
    /// Returns `(name, category)` pairs.
    fn known_sink_names(&self) -> Vec<(&'static str, SinkCategory)> {
        Vec::new()
    }

    /// All known taint source patterns for this language (e.g. "req.body",
    /// "process.env"). Used to populate the corpus registry's baseline source list.
    fn known_source_patterns(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Resolve the callee's receiver to its source module, for use in
    /// `classify_sink` when the caller doesn't already know the module.
    /// E.g., for `db.query(...)`, resolves `db` → `"pg"`.
    fn resolve_receiver_module(&self, call_text: &str) -> Option<String> {
        let receiver = call_text.split('.').next()?;
        self.resolve_name(receiver)
    }
}

/// Type information available for a function — ranging from nothing
/// (tree-sitter only) to a full symbol table (Oxc) to HIR types
/// (rust-analyzer).
#[derive(Debug, Clone, Copy)]
pub struct TypeContext<'a> {
    /// Always available (from import_resolver.rs)
    pub import_map: &'a ImportMap,
    /// Available when OxcProvider is active
    pub symbol_table: Option<&'a OxcSymbolTable>,
    /// Available when RustHirProvider is active
    pub hir_types: Option<&'a HirTypeMap>,
}

impl<'a> TypeContext<'a> {
    /// Build a context from just the per-file import map (the minimum that is
    /// always available). The richer symbol/type views start as `None`.
    #[must_use]
    pub fn from_import_map(import_map: &'a ImportMap) -> Self {
        Self {
            import_map,
            symbol_table: None,
            hir_types: None,
        }
    }
}

/// Owned, `Send + Sync` symbol table produced by parsing a JavaScript /
/// TypeScript file with Oxc (see [`crate::oxc_provider::build_oxc_symbol_table`]).
///
/// It is built once per file and then shared; it deliberately contains no
/// references into the Oxc allocator so it can be stored on the heap and passed
/// across threads.
#[derive(Debug, Clone, Default)]
pub struct OxcSymbolTable {
    /// Local binding name → module it resolves to.
    ///
    /// Every import (`import { Pool } from 'pg'` binds `Pool`), plus local
    /// variables that are derived from an import in their initializer
    /// (`const db = new Pool()` binds `db`, `const app = express()` binds
    /// `app`).
    pub bindings: FxHashMap<String, ResolvedModule>,

    /// Imported export name → module. `import { Request } from 'express'`
    /// records `Request`, so a later type annotation `req: Request` resolves
    /// without guessing.
    pub types: FxHashMap<String, ResolvedModule>,
}

/// A name's module resolution. At least one of [`package`](Self::package) /
/// [`path`](Self::path) is set for a resolved import; both are [`None`] when
/// resolution failed (e.g. a not-yet-installed dependency).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedModule {
    /// Package name from `package.json`, e.g. `"pg"` or `"@hono/node-server"`.
    pub package: Option<String>,

    /// Absolute path of the resolved entry file.
    pub path: Option<PathBuf>,
}

impl OxcSymbolTable {
    /// Resolve a local binding name to its source package, if any.
    #[must_use]
    pub fn package_for(&self, name: &str) -> Option<&str> {
        self.bindings
            .get(name)
            .and_then(|module| module.package.as_deref())
    }
}

/// Type information gathered from the rust-analyzer HIR when the
/// `RustHirProvider` (`--use-compiler`) is active.
///
/// Built once per project (see
/// [`crate::rust_hir_provider::build_hir_type_map`]) and shared; it is owned
/// and contains no references into the HIR database, so it can be moved across
/// threads after the database is dropped.
#[derive(Debug, Clone, Default)]
pub struct HirTypeMap {
    /// Base type name → fully qualified path of the type's definition, e.g.
    /// `"Json" → "axum::extract::Json"`. Collected from every parameter type
    /// seen in the workspace, so an annotation `Json<CreateUser>` resolves
    /// without an import map.
    pub type_paths: FxHashMap<String, String>,

    /// Per-function type-checked facts, keyed by `(file path, function name)`.
    pub functions: FxHashMap<(String, String), FunctionHirFact>,
}

/// Type-checked facts about a single function, extracted from the HIR.
#[derive(Debug, Clone, Default)]
pub struct FunctionHirFact {
    /// The function is `async fn`.
    pub is_async: bool,

    /// Trait names the return type is declared with (`-> impl ...`), e.g.
    /// `["IntoResponse"]` for an axum handler. This is the type-level proof
    /// that the function is a handler — the single fact the HIR gives us.
    /// Only populated for `impl Trait` return types; concrete types leave it
    /// empty.
    pub return_trait_bounds: Vec<String>,

    /// Parameters as `(name, rendered type)`, e.g.
    /// `("body", "Json<CreateUser>")`. Names are `None` for unnamed
    /// parameters (`_`).
    pub params: Vec<(Option<String>, String)>,
}

impl HirTypeMap {
    /// HIR facts for a fingerprinted function, if the HIR analysed that file.
    #[must_use]
    pub fn function_facts(&self, file_path: &str, function_name: &str) -> Option<&FunctionHirFact> {
        self.functions
            .get(&(file_path.to_owned(), function_name.to_owned()))
    }

    /// Resolve a type annotation's base name to its fully qualified path.
    /// `"Json"` → `Some("axum::extract::Json")`.
    #[must_use]
    pub fn resolve_type(&self, base_type_name: &str) -> Option<&str> {
        self.type_paths.get(base_type_name).map(String::as_str)
    }
}

/// HTTP framework packages. A parameter typed with any name imported from one
/// of these is user input, and a function with such a parameter is an HTTP
/// handler. This list grows only when a new framework is adopted, not when a
/// new method name exists inside any framework.
pub const HTTP_FRAMEWORK_PACKAGES: &[&str] = &[
    "express", "fastify", "koa", "hapi", "hono", "next", "nuxt", "h3", "polka", "elysia", "nest",
];

/// Packages whose objects are dangerous by construction: any method call on a
/// value imported from one of these is a sink in that category, regardless of
/// the method name (e.g. `db.query(...)` where `db` comes from `pg` needs no
/// entry for "query"). Kept small and stable — grows only when a new library
/// is adopted.
pub const PACKAGE_SINK_CATEGORIES: &[(&str, SinkCategory)] = &[
    // SQL / NoSQL database libraries
    ("pg", SinkCategory::SqlInjection),
    ("postgres", SinkCategory::SqlInjection),
    ("postgresql", SinkCategory::SqlInjection),
    ("mysql", SinkCategory::SqlInjection),
    ("mysql2", SinkCategory::SqlInjection),
    ("mariadb", SinkCategory::SqlInjection),
    ("sqlite", SinkCategory::SqlInjection),
    ("sqlite3", SinkCategory::SqlInjection),
    ("better-sqlite3", SinkCategory::SqlInjection),
    ("mssql", SinkCategory::SqlInjection),
    ("oracledb", SinkCategory::SqlInjection),
    ("sequelize", SinkCategory::SqlInjection),
    ("knex", SinkCategory::SqlInjection),
    ("typeorm", SinkCategory::SqlInjection),
    ("prisma", SinkCategory::SqlInjection),
    ("@prisma/client", SinkCategory::SqlInjection),
    ("mongo", SinkCategory::NoSqlInjection),
    ("mongodb", SinkCategory::NoSqlInjection),
    ("mongoose", SinkCategory::NoSqlInjection),
    // Shell execution
    ("child_process", SinkCategory::CommandInjection),
    ("shelljs", SinkCategory::CommandInjection),
    ("execa", SinkCategory::CommandInjection),
    ("cross-spawn", SinkCategory::CommandInjection),
    // HTTP clients (SSRF)
    ("node-fetch", SinkCategory::Ssrf),
    ("axios", SinkCategory::Ssrf),
    ("got", SinkCategory::Ssrf),
    ("superagent", SinkCategory::Ssrf),
    ("undici", SinkCategory::Ssrf),
    ("request", SinkCategory::Ssrf),
    // Filesystem (path traversal)
    ("fs", SinkCategory::PathTraversal),
    ("fs-extra", SinkCategory::PathTraversal),
];

/// O(1) lookup map built once from [`PACKAGE_SINK_CATEGORIES`].
/// Avoids the previous O(n) linear scan on every call to [`package_sink_category`].
static PACKAGE_SINK_MAP: std::sync::LazyLock<FxHashMap<&'static str, SinkCategory>> =
    std::sync::LazyLock::new(|| {
        PACKAGE_SINK_CATEGORIES
            .iter()
            .map(|&(k, v)| (k, v))
            .collect()
    });

/// O(1) membership set built once from [`HTTP_FRAMEWORK_PACKAGES`].
static HTTP_FRAMEWORK_SET: std::sync::LazyLock<FxHashSet<&'static str>> =
    std::sync::LazyLock::new(|| HTTP_FRAMEWORK_PACKAGES.iter().copied().collect());

/// Map a package name to the sink category of anything imported from it.
/// O(1) lookup via [`PACKAGE_SINK_MAP`].
pub fn package_sink_category(pkg: &str) -> Option<SinkCategory> {
    PACKAGE_SINK_MAP.get(pkg).copied()
}

/// Map a package name to its sink category using the language spec when
/// available, falling back to the hardcoded [`package_sink_category`] table.
pub fn package_sink_category_from_spec(
    pkg: &str,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) -> Option<SinkCategory> {
    if let Some(s) = spec {
        match s.package_category(pkg)? {
            frensense_lang::PackageCategory::SqlDatabase => Some(SinkCategory::SqlInjection),
            frensense_lang::PackageCategory::NoSqlDatabase => Some(SinkCategory::NoSqlInjection),
            frensense_lang::PackageCategory::HttpClient => Some(SinkCategory::Ssrf),
            frensense_lang::PackageCategory::TemplateEngine => Some(SinkCategory::Xss),
            frensense_lang::PackageCategory::CommandExecution => {
                Some(SinkCategory::CommandInjection)
            }
            frensense_lang::PackageCategory::FileSystem => Some(SinkCategory::PathTraversal),
            frensense_lang::PackageCategory::Deserialization => Some(SinkCategory::CodeExecution),
            _ => None,
        }
    } else {
        package_sink_category(pkg)
    }
}

/// Returns true if the package name belongs to a known HTTP framework.
/// Uses the language spec when available, falling back to the hardcoded
/// [`HTTP_FRAMEWORK_SET`].
pub(crate) fn is_http_framework_package(
    pkg: &str,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) -> bool {
    if let Some(s) = spec {
        matches!(
            s.package_category(pkg),
            Some(frensense_lang::PackageCategory::HttpFramework)
        )
    } else {
        HTTP_FRAMEWORK_SET.contains(pkg)
    }
}

/// Extract the base type name from a possibly-parameterized annotation.
/// `"Request"` → `"Request"`, `"Json<User>"` → `"Json"`, `"express.Request"` → `"Request"`.
pub fn base_type_name(annotation: &str) -> &str {
    let trimmed = annotation
        .trim()
        .trim_start_matches(|c: char| c == ':' || c.is_whitespace());
    let base = trimmed
        .split(['<', '[', '(', ' ', '\t', '\n'])
        .next()
        .unwrap_or(trimmed);
    base.rsplit('.').next().unwrap_or(base)
}

/// Implementation 1 — zero new dependencies.
///
/// Answers the semantic questions using the already-built per-file [`ImportMap`]
/// plus the corpus-learned source/sink registry. Framework-typed parameters and
/// package-owned receivers are resolved through the import system; the previous
/// name-based heuristics survive only as fallbacks for unannotated code.
///
/// Constructed per file: it owns that file's [`ImportMap`] and shares the
/// corpus registry via [`Arc`].
#[derive(Clone)]
pub struct ImportMapProvider {
    import_map: ImportMap,
    source_sink: Arc<CorpusSourceSinkRegistry>,
    environment: Option<crate::context::Environment>,
    spec: Option<Arc<dyn frensense_lang::LanguageSpec>>,
}

impl std::fmt::Debug for ImportMapProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportMapProvider")
            .field("import_map", &self.import_map)
            .field("source_sink", &self.source_sink)
            .field("environment", &self.environment)
            .field("spec", &self.spec.as_ref().map(|s| s.name()))
            .finish()
    }
}

impl ImportMapProvider {
    /// Build an import-map-backed provider for a single file.
    ///
    /// `environment` gates the name-based fallback so generic names like
    /// `name`/`data` are only tainted inside route handlers.
    #[must_use]
    pub fn new(
        import_map: ImportMap,
        source_sink: Arc<CorpusSourceSinkRegistry>,
        environment: Option<crate::context::Environment>,
    ) -> Self {
        Self {
            import_map,
            source_sink,
            environment,
            spec: None,
        }
    }

    /// Build an import-map-backed provider with a language spec.
    ///
    /// When a spec is available, the provider delegates package classification
    /// and source/sink knowledge to the spec instead of using hardcoded tables.
    #[must_use]
    pub fn with_spec(
        import_map: ImportMap,
        source_sink: Arc<CorpusSourceSinkRegistry>,
        environment: Option<crate::context::Environment>,
        spec: Arc<dyn frensense_lang::LanguageSpec>,
    ) -> Self {
        Self {
            import_map,
            source_sink,
            environment,
            spec: Some(spec),
        }
    }

    /// Access the per-file import map.
    #[must_use]
    pub fn import_map(&self) -> &ImportMap {
        &self.import_map
    }
}

impl SemanticProvider for ImportMapProvider {
    fn classify_param(&self, name: &str, type_annotation: Option<&str>) -> Option<TaintOrigin> {
        // 1. A corpus-learned source type wins outright.
        if let Some(annotation) = type_annotation {
            let clean = annotation.trim_start_matches(':').trim();
            if self.source_sink.is_source_type(clean) {
                return Some(TaintOrigin::UserInput);
            }
        }
        // 2. A type annotation imported from an HTTP framework is user input —
        //    the import system confirms it, no name guessing needed.
        if let Some(annotation) = type_annotation {
            let base = base_type_name(annotation);
            if let Some(package) = self.import_map.resolve(base)
                && is_http_framework_package(package, self.spec.as_deref())
            {
                return Some(TaintOrigin::UserInput);
            }
        }
        // 3. Fall back to name matching for unannotated parameters, delegating
        //    to the language spec when available for per-language taint origins.
        crate::data_flow::classify_param_name_in_context_with_spec(
            name,
            self.environment.as_ref(),
            self.spec.as_deref(),
        )
    }

    fn classify_sink(
        &self,
        call_text: &str,
        resolved_module: Option<&str>,
    ) -> Option<SinkCategory> {
        // 1. Resolve the receiver object against the import map first:
        //    `db.query(...)` where `db` is imported from `pg` is a sink without
        //    "query" ever having to appear in a sink list.
        if let Some(receiver) = call_text.split('.').next()
            && let Some(package) = self.import_map.resolve(receiver)
            && let Some(category) = package_sink_category_from_spec(package, self.spec.as_deref())
        {
            return Some(category);
        }
        // 2. A fully-qualified module (when the caller knows it) works the same way.
        if let Some(module) = resolved_module
            && let Some(category) = package_sink_category_from_spec(module, self.spec.as_deref())
        {
            return Some(category);
        }
        // 3. Fall back to the name-based registry.
        self.source_sink.is_sink_expr(call_text)
    }

    fn is_http_handler(&self, fp: &FunctionFingerprint, type_context: &TypeContext) -> bool {
        // Type-confirmed: if any type used by the function resolves to an HTTP
        // framework package, the import system has confirmed it — a single
        // signal is sufficient, no weak-heuristic vote needed.
        let type_confirmed = fp.type_usages.iter().any(|annotation| {
            type_context
                .import_map
                .resolve(annotation)
                .is_some_and(|p| is_http_framework_package(p, self.spec.as_deref()))
        });
        if type_confirmed {
            return true;
        }
        // Fall back to the ≥2 heuristic signals for untyped code.
        crate::function_role::classify_role_with_imports(fp, Some(type_context.import_map), None)
            == crate::function_role::FunctionRole::HttpHandler
    }

    fn file_imports(&self, package: &str) -> bool {
        self.import_map
            .name_to_package
            .values()
            .any(|p| p == package)
    }

    fn resolve_name(&self, name: &str) -> Option<String> {
        self.import_map.resolve(name).map(str::to_string)
    }

    fn known_sink_names(&self) -> Vec<(&'static str, SinkCategory)> {
        if let Some(s) = self.spec.as_deref() {
            s.known_sink_names()
                .iter()
                .map(|&(name, _desc)| (name, SinkCategory::from_sink_name(name)))
                .collect()
        } else {
            crate::corpus::source_sink::always_register_sinks_with_categories()
        }
    }

    fn known_source_patterns(&self) -> Vec<&'static str> {
        if let Some(s) = self.spec.as_deref() {
            s.known_source_patterns().to_vec()
        } else {
            crate::corpus::source_sink::always_register_source_patterns()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Environment;

    fn provider() -> ImportMapProvider {
        let mut import_map = ImportMap::new();
        import_map
            .name_to_package
            .insert("Request".to_string(), "express".to_string());
        import_map
            .name_to_package
            .insert("Context".to_string(), "hono".to_string());
        import_map
            .name_to_package
            .insert("db".to_string(), "pg".to_string());
        let mut registry = CorpusSourceSinkRegistry::default();
        registry.source_types.insert("Request".to_string(), 3);
        ImportMapProvider::new(
            import_map,
            Arc::new(registry),
            Some(Environment::RouteHandler),
        )
    }

    #[test]
    fn test_classify_param_by_source_type() {
        let p = provider();
        assert_eq!(
            p.classify_param("req", Some("Request")),
            Some(TaintOrigin::UserInput),
        );
        assert_eq!(
            p.classify_param("anything", Some("String")),
            None,
            "non-source type annotation must not taint"
        );
    }

    #[test]
    fn test_classify_param_http_framework_type() {
        let p = provider();
        assert_eq!(
            p.classify_param("c", Some("Context")),
            Some(TaintOrigin::UserInput),
            "hono.Context resolved via import map must be user input"
        );
    }

    #[test]
    fn test_classify_param_by_name() {
        let p = provider();
        assert_eq!(p.classify_param("req", None), Some(TaintOrigin::UserInput),);
        assert_eq!(
            p.classify_param("name", None),
            Some(TaintOrigin::UserInput),
            "`name` is tainted inside a RouteHandler"
        );
    }

    #[test]
    fn test_classify_param_name_not_tainted_outside_handler() {
        let p = ImportMapProvider::new(
            ImportMap::new(),
            Arc::new(CorpusSourceSinkRegistry::default()),
            Some(Environment::Utility),
        );
        assert_eq!(p.classify_param("name", None), None);
    }

    #[test]
    fn test_classify_sink_by_name() {
        let p = provider();
        assert_eq!(
            p.classify_sink("exec", None),
            Some(SinkCategory::CodeExecution),
        );
        assert_eq!(
            p.classify_sink("query", None),
            Some(SinkCategory::SqlInjection),
        );
        assert_eq!(
            p.classify_sink("safe_helper", None),
            None,
            "unknown call must not be a sink"
        );
    }

    #[test]
    fn test_classify_sink_resolves_receiver() {
        let p = provider();
        assert_eq!(
            p.classify_sink("db.query(...)", None),
            Some(SinkCategory::SqlInjection),
            "receiver `db` imported from `pg` must be a sink without a name entry"
        );
        assert_eq!(
            p.classify_sink("db.namedQuery(...)", None),
            Some(SinkCategory::SqlInjection),
            "arbitrary method on a pg-owned receiver is still a sink"
        );
    }

    #[test]
    fn test_file_imports_and_resolve_name() {
        let p = provider();
        assert!(p.file_imports("express"));
        assert!(!p.file_imports("react"));
        assert_eq!(p.resolve_name("Request"), Some("express".to_string()));
        assert_eq!(p.resolve_name("Unknown"), None);
    }

    #[test]
    fn test_is_http_handler_type_confirmed() {
        let p = provider();
        let import_map = p.import_map();
        let ctx = TypeContext::from_import_map(import_map);

        // A typed parameter resolving to an HTTP framework is a handler on its
        // own — no decorator, no res.send(), no req param name.
        let handler = FunctionFingerprint {
            type_usages: vec!["Request".to_string()],
            ..empty_fingerprint()
        };
        assert!(p.is_http_handler(&handler, &ctx));

        let hono = FunctionFingerprint {
            type_usages: vec!["Context".to_string()],
            ..empty_fingerprint()
        };
        assert!(p.is_http_handler(&hono, &ctx));

        let plain = empty_fingerprint();
        assert!(!p.is_http_handler(&plain, &ctx));
    }

    #[test]
    fn test_is_http_handler_decorator_fallback() {
        let p = provider();
        let import_map = p.import_map();
        let ctx = TypeContext::from_import_map(import_map);

        let decorated = FunctionFingerprint {
            has_http_decorator: true,
            ..empty_fingerprint()
        };
        assert!(p.is_http_handler(&decorated, &ctx));
    }

    fn empty_fingerprint() -> FunctionFingerprint {
        FunctionFingerprint {
            file_path: String::new(),
            function_name: String::new(),
            line: 0,
            language: String::new(),
            ngram_hashes: Vec::new(),
            weighted_ngram_hashes: Default::default(),
            signature_ngrams: Vec::new(),
            param_type_ngrams: Vec::new(),
            name_segments: Vec::new(),
            structural_markers: Vec::new(),
            type_usages: Vec::new(),
            comment_density: 0.0,
            semantic_markers: Vec::new(),
            skeleton: Vec::new(),
            skeleton_hashes: Vec::new(),
            control_flow_hashes: Vec::new(),
            control_flow_sequence: Vec::new(),
            api_calls: Vec::new(),
            api_call_segments: Vec::new(),
            property_accesses: Vec::new(),
            motif_hashes: Vec::new(),
            data_flow_path_hashes: Vec::new(),
            raw_call_names: Vec::new(),
            param_names: Vec::new(),
            tainted_api_calls: Vec::new(),
            config_literal_hashes: Vec::new(),
            argument_call_types: Vec::new(),
            literal_pattern_hashes: Vec::new(),
            has_http_decorator: false,
            is_registered_handler: false,
            export_handler_kind: None,
        }
    }
}
