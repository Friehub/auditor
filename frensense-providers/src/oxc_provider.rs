// SPDX-License-Identifier: MIT

//! Implementation 2 — [`OxcProvider`]: exact JavaScript / TypeScript
//! resolution via the Oxc compiler.
//!
//! Oxc gives us what the tree-sitter heuristics could never have:
//!
//! - Real module resolution (bare imports, scoped packages, tsconfig path
//!   aliases, `exports`/`main` fields, dynamic `import()`).
//! - The local-name → package table for the whole file, including names
//!   derived from imports (`const db = new Pool()` binds `db` to `pg`).
//! - Barrel re-export following, so `@hono/node-server` (which re-exports
//!   `hono`) is still classified as `hono`.
//!
//! [`OxcProvider`] implements the same [`SemanticProvider`] contract as
//! [`frensense_engine::semantic::ImportMapProvider`], but answers from the Oxc-built
//! [`OxcSymbolTable`] instead of the tree-sitter [`frensense_engine::import_resolver::ImportMap`].
//! The name-based fallbacks survive only for unannotated code.
//!
//! This module is compiled only under the `oxc` feature.

use std::path::Path;
use std::sync::Arc;

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression, MemberExpression, VariableDeclarator};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_resolver::{ResolveOptions, Resolver};
use oxc_span::SourceType;
use oxc_syntax::module_record::ImportImportName;
use rustc_hash::FxHashMap;

use frensense_engine::context::Environment;
use frensense_engine::corpus::source_sink::{CorpusSourceSinkRegistry, SinkCategory};
use frensense_engine::data_flow::TaintOrigin;
use frensense_engine::fingerprint::FunctionFingerprint;
use frensense_engine::semantic::{
    HTTP_FRAMEWORK_PACKAGES, OxcSymbolTable, PACKAGE_SINK_CATEGORIES, ResolvedModule,
    SemanticProvider, TypeContext, base_type_name, package_sink_category,
};

/// Default set of extensions the resolver tries, in order.
const TS_EXTENSIONS: &[&str] = &[
    ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".json", ".d.ts", ".node",
];

/// Maximum depth for following a module request across re-exporting barrels.
const MAX_BARREL_DEPTH: usize = 4;

/// Parse one JavaScript / TypeScript file with Oxc and build the owned
/// [`OxcSymbolTable`] for it.
///
/// `path` is used only to pick the dialect (`.ts` vs `.tsx` vs `.js`) and as
/// the base directory for module resolution; the source text itself is passed
/// in so callers can analyse in-memory buffers.
///
/// Resolution failures are not fatal: uninstalled or unresolvable imports just
/// produce a module with no package/path, so a missing `node_modules` degrades
/// to name-based classification instead of erroring.
#[must_use]
pub fn build_oxc_symbol_table(source: &str, path: &Path) -> OxcSymbolTable {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path).unwrap_or_else(|_| SourceType::ts());
    let parser_return = Parser::new(&allocator, source, source_type).parse();
    let program = &parser_return.program;

    let resolver = ts_resolver(path);
    let mut table = OxcSymbolTable::default();

    // 1. Every static import binds its local name to the resolved module.
    //    `import { Pool } from 'pg'`          → bindings["Pool"] = pg
    //    `import express from 'express'`      → bindings["express"] = express
    //    `import * as http from 'node:http'`  → bindings["http"] = node:http
    //    The *exported* name is also recorded for type-annotation resolution.
    for entry in &parser_return.module_record.import_entries {
        let local = entry.local_name.name.as_str().to_string();
        let request = entry.module_request.name.as_str();
        let resolved = resolve_module(&resolver, path, request);
        table.bindings.insert(local.clone(), resolved.clone());
        if let ImportImportName::Name(export_name) = &entry.import_name {
            table
                .types
                .insert(export_name.name.as_str().to_string(), resolved);
        }
    }

    // 2. Local names derived from an import in their initializer:
    //    `const db = new Pool()`   → bindings["db"] = pg
    //    `const app = express()`   → bindings["app"] = express
    //    `const c = createServer()` → bindings["c"] = @hono/node-server (→ hono)
    //    Later declarators can chain off earlier ones (`const client = require('pg')`
    //    then `const db = new client.Client()`), so the collector resolves against
    //    the map it is growing.
    let mut collector = BindingCollector {
        resolved: &mut table.bindings,
    };
    collector.visit_program(program);

    table
}

/// An Oxc resolver configured for TypeScript/JavaScript resolution.
fn ts_resolver(cwd: &Path) -> Resolver {
    let mut options = ResolveOptions::default();
    options.cwd = Some(cwd.parent().unwrap_or(cwd).to_path_buf());
    options.extensions = TS_EXTENSIONS.iter().map(|s| (*s).to_string()).collect();
    options.condition_names = ["import", "require", "node", "default", "types"]
        .map(str::to_string)
        .to_vec();
    options.main_fields = ["module", "types", "main"].map(str::to_string).to_vec();
    options.main_files = ["index.ts", "index.tsx", "index.js", "index"]
        .map(str::to_string)
        .to_vec();
    Resolver::new(options)
}

/// Resolve a module request to its package name and entry file.
///
/// The request is resolved against the directory containing `from`. A relative
/// import (`./util`) resolves to a file but no package; a bare import (`pg`)
/// resolves to a package. When the direct package is not one the engine knows
/// about, re-exporting barrels are followed (up to [`MAX_BARREL_DEPTH`]) so
/// that, e.g. `@hono/node-server` — which re-exports `hono` — still lands on
/// the known `hono` package.
fn resolve_module(resolver: &Resolver, from: &Path, request: &str) -> ResolvedModule {
    let direct = resolve_once(resolver, from, request);
    if direct.package.as_deref().is_some_and(is_known_package) {
        return direct;
    }
    follow_barrels(resolver, from, request, MAX_BARREL_DEPTH)
}

/// Single-step resolution of `request` from `from`'s directory.
fn resolve_once(resolver: &Resolver, from: &Path, request: &str) -> ResolvedModule {
    let base = from.parent().unwrap_or(from);
    match resolver.resolve(base, request) {
        Ok(resolution) => {
            let package = resolution
                .package_json()
                .and_then(|package_json| package_json.name())
                .map(str::to_string);
            ResolvedModule {
                package,
                path: Some(resolution.path().to_path_buf()),
            }
        }
        Err(_) => ResolvedModule::default(),
    }
}

/// Follow re-export barrels: parse the resolved file and, for every name it
/// re-exports, resolve the re-export target in turn. Returns the first module
/// that lands on a known package (preferring it over the direct, unknown one),
/// or the original resolution.
fn follow_barrels(resolver: &Resolver, from: &Path, request: &str, depth: usize) -> ResolvedModule {
    if depth == 0 {
        return resolve_once(resolver, from, request);
    }
    let resolved = resolve_once(resolver, from, request);
    let Some(file_path) = &resolved.path else {
        return resolved;
    };

    let Ok(source) = std::fs::read_to_string(file_path) else {
        return resolved;
    };
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(file_path).unwrap_or_else(|_| SourceType::ts());
    let parser_return = Parser::new(&allocator, &source, source_type).parse();
    let module_record = &parser_return.module_record;
    if !module_record.has_module_syntax {
        return resolved;
    }

    // Every `export ... from 'mod'` this barrel performs is followed — with
    // the re-export resolved relative to the barrel's own directory, not the
    // original file's.
    for export in &module_record.indirect_export_entries {
        let Some(request) = &export.module_request else {
            continue;
        };
        let next_request = request.name.as_str();
        let next = follow_barrels(resolver, file_path, next_request, depth - 1);
        if next.package.as_deref().is_some_and(is_known_package) {
            return next;
        }
    }

    resolved
}

/// Is this package one the engine classifies against (an HTTP framework or a
/// package-owned sink)? If not, we keep looking through barrels.
fn is_known_package(package: &str) -> bool {
    HTTP_FRAMEWORK_PACKAGES.contains(&package) || package_sink_category(package).is_some()
}

/// `true` for a non-relative, non-absolute, non-builtin module request
/// (`pg`, `@scope/pkg`, `@prisma/client`) as opposed to `./x`, `../x`, `/x`,
/// `node:x`.
fn is_bare_request(request: &str) -> bool {
    !request.starts_with('.')
        && !request.starts_with('/')
        && !request.starts_with('\\')
        && !request.starts_with("node:")
        && !request.contains(':')
}

/// Walks a file's AST collecting names whose initializer derives from an
/// import: `const db = new Pool()`, `const app = express()`,
/// `const client = require('pg')`. Resolves against the map it is itself
/// growing, so derived bindings chain (`new client.Client()` after
/// `const client = require('pg')`).
struct BindingCollector<'t> {
    resolved: &'t mut FxHashMap<String, ResolvedModule>,
}

impl<'a> Visit<'a> for BindingCollector<'_> {
    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(init) = &it.init
            && let Some(name) = it.id.get_identifier_name()
            && !self.resolved.contains_key(name.as_str())
            && let Some(module) = resolve_init(init, self.resolved)
        {
            self.resolved.insert(name.as_str().to_string(), module);
        }
        walk::walk_variable_declarator(self, it);
    }
}

/// Resolve a declarator's initializer to the module it was created from, if it
/// is derived from an import.
fn resolve_init<'a>(
    init: &'a Expression<'a>,
    bindings: &FxHashMap<String, ResolvedModule>,
) -> Option<ResolvedModule> {
    match init {
        Expression::NewExpression(new) => resolve_expression(&new.callee, bindings),
        Expression::CallExpression(call) => {
            // `const client = require('pg')` — CommonJS equivalent of an import.
            if is_require(call) {
                return require_target(call);
            }
            resolve_expression(&call.callee, bindings)
        }
        other => resolve_expression(other, bindings),
    }
}

/// Is this call a `require(...)`?
fn is_require(call: &CallExpression) -> bool {
    matches!(&call.callee, Expression::Identifier(id) if id.name == "require")
}

/// The module requested by `require('pg')` / `require('./util')`.
fn require_target(call: &CallExpression<'_>) -> Option<ResolvedModule> {
    let literal = call.arguments.first()?.as_expression()?;
    let Expression::StringLiteral(specifier) = literal else {
        return None;
    };
    let request = specifier.value.as_str();
    if !is_bare_request(request) {
        return None;
    }
    Some(ResolvedModule {
        package: Some(request.to_string()),
        path: None,
    })
}

/// Reduce an expression to the module it was created from, following member
/// chains and type/paren wrappers: `Pool` → pg, `express.Router` → express.
fn resolve_expression<'a>(
    expression: &'a Expression<'a>,
    bindings: &FxHashMap<String, ResolvedModule>,
) -> Option<ResolvedModule> {
    match expression {
        Expression::Identifier(id) => bindings.get(id.name.as_str()).cloned(),
        Expression::ParenthesizedExpression(parenthesized) => {
            resolve_expression(&parenthesized.expression, bindings)
        }
        Expression::TSAsExpression(as_expression) => {
            resolve_expression(&as_expression.expression, bindings)
        }
        other => other
            .as_member_expression()
            .and_then(|member| resolve_member(member, bindings)),
    }
}

fn resolve_member<'a>(
    member: &'a MemberExpression<'a>,
    bindings: &FxHashMap<String, ResolvedModule>,
) -> Option<ResolvedModule> {
    resolve_expression(member.object(), bindings)
}

/// Implementation 2 — exact resolution for JavaScript / TypeScript.
///
/// Answers the [`SemanticProvider`] questions from the [`OxcSymbolTable`] built
/// by [`build_oxc_symbol_table`]. Where Oxc knows the module a name comes from,
/// that wins; the corpus registry and name heuristics remain as fallbacks for
/// code Oxc cannot resolve (unannotated params, unrecognised receivers).
#[derive(Debug, Clone)]
pub struct OxcProvider {
    symbol_table: Arc<OxcSymbolTable>,
    source_sink: Arc<CorpusSourceSinkRegistry>,
    environment: Option<Environment>,
}

impl OxcProvider {
    /// Build a provider over an already-parsed symbol table.
    #[must_use]
    pub fn new(
        symbol_table: Arc<OxcSymbolTable>,
        source_sink: Arc<CorpusSourceSinkRegistry>,
        environment: Option<Environment>,
    ) -> Self {
        Self {
            symbol_table,
            source_sink,
            environment,
        }
    }

    /// Parse `source` (a file at `path`) and build a provider for it.
    #[must_use]
    pub fn analyze(
        source: &str,
        path: &Path,
        source_sink: Arc<CorpusSourceSinkRegistry>,
        environment: Option<Environment>,
    ) -> Self {
        Self::new(
            Arc::new(build_oxc_symbol_table(source, path)),
            source_sink,
            environment,
        )
    }

    /// Access the underlying symbol table.
    #[must_use]
    pub fn symbol_table(&self) -> &OxcSymbolTable {
        &self.symbol_table
    }
}

impl SemanticProvider for OxcProvider {
    fn classify_param(&self, name: &str, type_annotation: Option<&str>) -> Option<TaintOrigin> {
        // 1. A corpus-learned source type wins outright.
        if let Some(annotation) = type_annotation {
            let clean = annotation.trim_start_matches(':').trim();
            if self.source_sink.is_source_type(clean) {
                return Some(TaintOrigin::UserInput);
            }
        }
        // 2. A type annotation imported from an HTTP framework is user input —
        //    Oxc confirmed the type name resolves to that package.
        if let Some(annotation) = type_annotation {
            let base = base_type_name(annotation);
            if let Some(module) = self.symbol_table.types.get(base)
                && module
                    .package
                    .as_deref()
                    .is_some_and(|p| HTTP_FRAMEWORK_PACKAGES.contains(&p))
            {
                return Some(TaintOrigin::UserInput);
            }
        }
        // 3. Fall back to name matching for unannotated parameters.
        frensense_engine::data_flow::classify_param_name_in_context(name, self.environment.as_ref())
    }

    fn classify_sink(
        &self,
        call_text: &str,
        resolved_module: Option<&str>,
    ) -> Option<SinkCategory> {
        // 1. Resolve the receiver object against the Oxc symbol table:
        //    `db.query(...)` where `db` is `new Pool()` from `pg` is a sink
        //    without "query" ever having to appear in a sink list.
        if let Some(receiver) = call_text.split('.').next()
            && let Some(package) = self.symbol_table.package_for(receiver)
            && let Some(category) = package_sink_category(package)
        {
            return Some(category);
        }
        // 2. A fully-qualified module (when the caller knows it) works the same way.
        if let Some(module) = resolved_module
            && let Some(category) = package_sink_category(module)
        {
            return Some(category);
        }
        // 3. Method-name-based fallback for DB operations when the receiver
        //    can't be resolved (e.g., function parameters like `db` in
        //    `ContributionsDAO(db)`). If the method name starts with a known
        //    DB operation, classify it as a sink regardless of the receiver.
        if let Some(method) = call_text
            .split('.')
            .nth(1)
            .and_then(|s| s.split('(').next())
        {
            let m = method.to_lowercase();
            if m.starts_with("query")
                || m.starts_with("exec")
                || m.starts_with("raw")
                || m.starts_with("execute")
                || m.starts_with("update")
                || m.starts_with("insert")
                || m.starts_with("delete")
                || m.starts_with("remove")
                || m.starts_with("find")
                || m.starts_with("aggregate")
                || m.starts_with("count")
                || m.starts_with("bulk")
            {
                return Some(SinkCategory::SqlInjection);
            }
            if m.starts_with("spawn") || m.starts_with("fork") {
                return Some(SinkCategory::CommandInjection);
            }
            if m.starts_with("read")
                || m.starts_with("write")
                || m.starts_with("append")
                || m.starts_with("readdir")
                || m.starts_with("unlink")
                || m.starts_with("rename")
                || m.starts_with("mkdir")
                || m.starts_with("rmdir")
                || m.starts_with("stat")
                || m.starts_with("access")
            {
                return Some(SinkCategory::PathTraversal);
            }
        }
        // 4. Fall back to the name-based registry.
        self.source_sink.is_sink_expr(call_text)
    }

    fn is_http_handler(&self, fp: &FunctionFingerprint, type_context: &TypeContext) -> bool {
        // Type-confirmed: if any type used by the function resolves to an HTTP
        // framework package, Oxc has confirmed it — a single signal suffices.
        let type_confirmed = fp.type_usages.iter().any(|annotation| {
            self.symbol_table
                .types
                .get(annotation)
                .is_some_and(|module| {
                    module
                        .package
                        .as_deref()
                        .is_some_and(|package| HTTP_FRAMEWORK_PACKAGES.contains(&package))
                })
        });
        if type_confirmed {
            return true;
        }
        // Fall back to the ≥2 heuristic signals for untyped code.
        frensense_engine::function_role::classify_role_with_imports(
            fp,
            Some(type_context.import_map),
            None,
        ) == frensense_engine::function_role::FunctionRole::HttpHandler
    }

    fn file_imports(&self, package: &str) -> bool {
        self.symbol_table
            .bindings
            .values()
            .any(|module| module.package.as_deref() == Some(package))
    }

    fn resolve_name(&self, name: &str) -> Option<String> {
        self.symbol_table.package_for(name).map(str::to_string)
    }

    fn known_sink_names(&self) -> Vec<(&'static str, SinkCategory)> {
        // Global sinks that don't require module resolution — these are always
        // dangerous regardless of which file imports them.
        let mut sinks: Vec<(&str, SinkCategory)> = vec![
            ("eval", SinkCategory::CodeExecution),
            ("Function", SinkCategory::CodeExecution),
            ("setTimeout", SinkCategory::CodeExecution),
            ("setInterval", SinkCategory::CodeExecution),
            ("require", SinkCategory::CodeExecution),
            ("import", SinkCategory::CodeExecution),
            // MongoDB NoSQL operator sinks (used as object property keys)
            ("$where", SinkCategory::NoSqlInjection),
            ("$regex", SinkCategory::NoSqlInjection),
            ("$gt", SinkCategory::NoSqlInjection),
            ("$lt", SinkCategory::NoSqlInjection),
            ("$ne", SinkCategory::NoSqlInjection),
            ("$in", SinkCategory::NoSqlInjection),
            ("$nin", SinkCategory::NoSqlInjection),
            ("$exists", SinkCategory::NoSqlInjection),
            ("$expr", SinkCategory::NoSqlInjection),
            ("$function", SinkCategory::NoSqlInjection),
            ("$accumulator", SinkCategory::NoSqlInjection),
            // Prototype pollution (framework-level)
            ("Object.assign", SinkCategory::CodeExecution),
            ("_.merge", SinkCategory::CodeExecution),
            ("lodash.merge", SinkCategory::CodeExecution),
            ("_.defaultsDeep", SinkCategory::CodeExecution),
            ("_.set", SinkCategory::CodeExecution),
            ("$.extend", SinkCategory::CodeExecution),
            ("jQuery.extend", SinkCategory::CodeExecution),
            ("setPrototypeOf", SinkCategory::CodeExecution),
            // SSTI — template engine renders
            ("ejs.render", SinkCategory::CodeExecution),
            ("ejs.renderFile", SinkCategory::CodeExecution),
            ("pug.compile", SinkCategory::CodeExecution),
            ("pug.render", SinkCategory::CodeExecution),
            ("handlebars.compile", SinkCategory::CodeExecution),
            ("handlebars.render", SinkCategory::CodeExecution),
            ("nunjucks.render", SinkCategory::CodeExecution),
            ("nunjucks.renderString", SinkCategory::CodeExecution),
            ("nunjucks.renderFile", SinkCategory::CodeExecution),
            ("marko.render", SinkCategory::CodeExecution),
            ("eta.render", SinkCategory::CodeExecution),
            ("swig.render", SinkCategory::CodeExecution),
            ("liquid.render", SinkCategory::CodeExecution),
            ("mustache.render", SinkCategory::CodeExecution),
            ("jade.render", SinkCategory::CodeExecution),
            (
                "react-dom/server.renderToString",
                SinkCategory::CodeExecution,
            ),
            (
                "vue-server-renderer.renderToString",
                SinkCategory::CodeExecution,
            ),
            // Insecure deserialization
            ("yaml.load", SinkCategory::CodeExecution),
            ("js-yaml.load", SinkCategory::CodeExecution),
            ("DOMParser", SinkCategory::CodeExecution),
            // XSS
            ("innerHTML", SinkCategory::Xss),
            ("outerHTML", SinkCategory::Xss),
            ("document.write", SinkCategory::Xss),
            ("document.writeln", SinkCategory::Xss),
            ("dangerouslySetInnerHTML", SinkCategory::Xss),
            // Open redirect
            ("location.href", SinkCategory::OpenRedirect),
            ("window.location", SinkCategory::OpenRedirect),
        ];

        // Package-level sinks from PACKAGE_SINK_CATEGORIES — any method call
        // on a value from these packages is a sink, regardless of method name.
        for &(_package, ref category) in PACKAGE_SINK_CATEGORIES {
            // The package itself isn't a sink name; the methods on it are.
            // We register the package so `classify_sink` can resolve receivers.
            // But for the fallback name registry, we add common method names
            // that are always dangerous on these packages.
            match category {
                SinkCategory::SqlInjection => {
                    sinks.push(("query", SinkCategory::SqlInjection));
                    sinks.push(("execute", SinkCategory::SqlInjection));
                    sinks.push(("executeRaw", SinkCategory::SqlInjection));
                    sinks.push(("queryRaw", SinkCategory::SqlInjection));
                    sinks.push(("raw", SinkCategory::SqlInjection));
                    sinks.push(("prepare", SinkCategory::SqlInjection));
                    sinks.push(("findOne", SinkCategory::SqlInjection));
                    sinks.push(("findMany", SinkCategory::SqlInjection));
                    sinks.push(("create", SinkCategory::SqlInjection));
                    sinks.push(("update", SinkCategory::SqlInjection));
                    sinks.push(("delete", SinkCategory::SqlInjection));
                    sinks.push(("aggregate", SinkCategory::SqlInjection));
                    sinks.push(("upsert", SinkCategory::SqlInjection));
                }
                SinkCategory::CommandInjection => {
                    sinks.push(("exec", SinkCategory::CommandInjection));
                    sinks.push(("execSync", SinkCategory::CommandInjection));
                    sinks.push(("spawn", SinkCategory::CommandInjection));
                    sinks.push(("spawnSync", SinkCategory::CommandInjection));
                    sinks.push(("execFile", SinkCategory::CommandInjection));
                    sinks.push(("execFileSync", SinkCategory::CommandInjection));
                }
                SinkCategory::Ssrf => {
                    sinks.push(("fetch", SinkCategory::Ssrf));
                    sinks.push(("get", SinkCategory::Ssrf));
                    sinks.push(("post", SinkCategory::Ssrf));
                    sinks.push(("put", SinkCategory::Ssrf));
                    sinks.push(("request", SinkCategory::Ssrf));
                }
                SinkCategory::PathTraversal => {
                    sinks.push(("readFile", SinkCategory::PathTraversal));
                    sinks.push(("writeFile", SinkCategory::PathTraversal));
                    sinks.push(("readFileSync", SinkCategory::PathTraversal));
                    sinks.push(("writeFileSync", SinkCategory::PathTraversal));
                    sinks.push(("read", SinkCategory::PathTraversal));
                    sinks.push(("write", SinkCategory::PathTraversal));
                    sinks.push(("open", SinkCategory::PathTraversal));
                    sinks.push(("stat", SinkCategory::PathTraversal));
                    sinks.push(("access", SinkCategory::PathTraversal));
                    sinks.push(("unlink", SinkCategory::PathTraversal));
                    sinks.push(("readdir", SinkCategory::PathTraversal));
                }
                _ => {}
            }
        }

        // Deduplicate by name (keep first occurrence)
        let mut seen = rustc_hash::FxHashSet::default();
        sinks.retain(|(name, _)| seen.insert(*name));
        sinks
    }

    fn known_source_patterns(&self) -> Vec<&'static str> {
        vec![
            "req.query",
            "req.body",
            "req.params",
            "req.headers",
            "req.cookies",
            "req.file",
            "req.files",
            "ctx.request",
            "ctx.query",
            "ctx.params",
            "ctx.body",
            "event.body",
            "request.body",
            "request.query",
            "process.argv",
            "process.env",
            "c.req",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// Write a fake `node_modules` tree so the resolver can actually resolve
    /// bare imports during the test. Returns the project root.
    fn fake_project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, package_name) in [("pg", "pg"), ("express", "express")] {
            let package_root = dir.path().join("node_modules").join(name);
            std::fs::create_dir_all(&package_root).expect("mkdir");
            let mut package_json =
                std::fs::File::create(package_root.join("package.json")).expect("package.json");
            write!(package_json, r#"{{"name":"{package_name}"}}"#).expect("write");
            let entry = if name == "pg" {
                "index.js"
            } else {
                "index.d.ts"
            };
            std::fs::File::create(package_root.join(entry)).expect("entry");
        }
        dir
    }

    fn read_main_ts(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("main.ts")
    }

    #[test]
    fn test_build_table_binds_imports() {
        let project = fake_project();
        let path = read_main_ts(&project);
        let source = r#"
            import { Pool } from 'pg';
            import express from 'express';
            import { Request } from 'express';
        "#;
        let table = build_oxc_symbol_table(source, &path);

        assert_eq!(
            table
                .bindings
                .get("Pool")
                .and_then(|m| m.package.as_deref()),
            Some("pg")
        );
        assert_eq!(
            table
                .bindings
                .get("express")
                .and_then(|m| m.package.as_deref()),
            Some("express")
        );
        assert_eq!(
            table
                .types
                .get("Request")
                .and_then(|m| m.package.as_deref()),
            Some("express")
        );
        assert_eq!(
            table.types.get("Request").and_then(|m| m.path.as_deref()),
            Some(
                project
                    .path()
                    .join("node_modules/express/index.d.ts")
                    .as_path()
            ),
        );
    }

    #[test]
    fn test_build_table_follows_new_and_call_initializers() {
        let project = fake_project();
        let path = read_main_ts(&project);
        let source = r#"
            import { Pool } from 'pg';
            import express from 'express';
            const db = new Pool();
            const app = express();
        "#;
        let table = build_oxc_symbol_table(source, &path);

        assert_eq!(
            table.package_for("db"),
            Some("pg"),
            "new Pool() binds db to pg"
        );
        assert_eq!(
            table.package_for("app"),
            Some("express"),
            "express() binds app to express"
        );
    }

    #[test]
    fn test_build_table_follows_require() {
        let project = fake_project();
        let path = read_main_ts(&project);
        let source = r#"
            const client = require('pg');
            const db = new client.Client();
        "#;
        let table = build_oxc_symbol_table(source, &path);

        assert_eq!(table.package_for("client"), Some("pg"));
        assert_eq!(
            table.package_for("db"),
            Some("pg"),
            "new client.Client() binds db to pg"
        );
    }

    #[test]
    fn test_build_table_ignores_unresolvable_imports() {
        let project = fake_project();
        let path = read_main_ts(&project);
        let source = r#"
            import { thing } from 'this-package-does-not-exist';
            const x = thing();
        "#;
        let table = build_oxc_symbol_table(source, &path);

        assert_eq!(
            table.bindings.get("thing").map(|m| m.package.as_deref()),
            Some(None)
        );
        assert_eq!(table.package_for("x"), None);
    }

    #[test]
    fn test_build_table_follows_barrel_re_export() {
        let dir = tempfile::tempdir().expect("tempdir");

        // @hono/node-server re-exports a symbol from `hono`.
        let node_server = dir.path().join("node_modules/@hono/node-server");
        std::fs::create_dir_all(&node_server).expect("mkdir");
        write!(
            std::fs::File::create(node_server.join("package.json")).expect("package.json"),
            r#"{{"name":"@hono/node-server"}}"#
        )
        .expect("write");
        write!(
            std::fs::File::create(node_server.join("index.d.ts")).expect("index.d.ts"),
            "export {{ createServer }} from 'hono';\n"
        )
        .expect("write");

        let hono = dir.path().join("node_modules/hono");
        std::fs::create_dir_all(&hono).expect("mkdir");
        write!(
            std::fs::File::create(hono.join("package.json")).expect("package.json"),
            r#"{{"name":"hono"}}"#
        )
        .expect("write");
        std::fs::File::create(hono.join("index.d.ts")).expect("index.d.ts");

        let path = dir.path().join("main.ts");
        let source = "import * as hono from '@hono/node-server';\n";
        let table = build_oxc_symbol_table(source, &path);

        assert_eq!(
            table.package_for("hono"),
            Some("hono"),
            "barrel re-export from @hono/node-server must resolve to the hono package"
        );
    }

    fn registry() -> Arc<CorpusSourceSinkRegistry> {
        let mut registry = CorpusSourceSinkRegistry::default();
        registry.source_types.insert("Request".to_string(), 3);
        Arc::new(registry)
    }

    #[test]
    fn test_provider_classify_param_via_oxc_types() {
        let mut table = OxcSymbolTable::default();
        table.types.insert(
            "Request".to_string(),
            ResolvedModule {
                package: Some("express".to_string()),
                path: None,
            },
        );
        let p = OxcProvider::new(Arc::new(table), registry(), Some(Environment::RouteHandler));

        assert_eq!(
            p.classify_param("req", Some("Request")),
            Some(TaintOrigin::UserInput),
            "Request confirmed by oxc must be user input"
        );
        assert_eq!(
            p.classify_param("anything", Some("String")),
            None,
            "non-source type annotation must not taint"
        );
        assert_eq!(
            p.classify_param("req", None),
            Some(TaintOrigin::UserInput),
            "name fallback still applies to unannotated params"
        );
    }

    #[test]
    fn test_provider_classify_sink_via_oxc_bindings() {
        let mut table = OxcSymbolTable::default();
        table.bindings.insert(
            "db".to_string(),
            ResolvedModule {
                package: Some("pg".to_string()),
                path: None,
            },
        );
        let p = OxcProvider::new(Arc::new(table), registry(), None);

        assert_eq!(
            p.classify_sink("db.query(...)", None),
            Some(SinkCategory::SqlInjection),
            "receiver `db` bound to pg by oxc must be a sink without a name entry"
        );
        assert_eq!(
            p.classify_sink("db.namedQuery(...)", None),
            Some(SinkCategory::SqlInjection),
            "arbitrary method on a pg-owned receiver is still a sink"
        );
        assert_eq!(p.classify_sink("safe_helper(...)", None), None);
    }

    #[test]
    fn test_provider_resolve_name_and_file_imports() {
        let mut table = OxcSymbolTable::default();
        table.bindings.insert(
            "Pool".to_string(),
            ResolvedModule {
                package: Some("pg".to_string()),
                path: None,
            },
        );
        let p = OxcProvider::new(Arc::new(table), registry(), None);

        assert_eq!(p.resolve_name("Pool"), Some("pg".to_string()));
        assert_eq!(p.resolve_name("Unknown"), None);
        assert!(p.file_imports("pg"));
        assert!(!p.file_imports("express"));
    }

    #[test]
    fn test_provider_is_http_handler_type_confirmed() {
        let mut table = OxcSymbolTable::default();
        table.types.insert(
            "Request".to_string(),
            ResolvedModule {
                package: Some("express".to_string()),
                path: None,
            },
        );
        table.types.insert(
            "Context".to_string(),
            ResolvedModule {
                package: Some("hono".to_string()),
                path: None,
            },
        );
        let p = OxcProvider::new(Arc::new(table), registry(), None);
        let import_map = frensense_engine::import_resolver::ImportMap::new();
        let ctx = TypeContext::from_import_map(&import_map);

        let handler = FunctionFingerprint {
            type_usages: vec!["Request".to_string()],
            ..empty_fingerprint()
        };
        assert!(
            p.is_http_handler(&handler, &ctx),
            "Request → express is type-confirmed"
        );

        let hono = FunctionFingerprint {
            type_usages: vec!["Context".to_string()],
            ..empty_fingerprint()
        };
        assert!(
            p.is_http_handler(&hono, &ctx),
            "Context → hono is type-confirmed"
        );

        let plain = empty_fingerprint();
        assert!(!p.is_http_handler(&plain, &ctx));
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
