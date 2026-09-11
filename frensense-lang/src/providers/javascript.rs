// SPDX-License-Identifier: MIT
//! JavaScript and TypeScript [`LanguageSpec`] implementations.
//!
//! Both share the same AST grammar (TypeScript is a superset of JavaScript in
//! tree-sitter-typescript). They differ only in the `tree_sitter_language()`
//! call and file extensions.

use tree_sitter::Node;

use crate::spec::{
    call_last_segment, node_text, Import, LanguageSpec, NodeRole, PackageCategory, PropagatorRule,
    SanitizerKind, TaintOrigin,
};

// ── Shared AST logic ──────────────────────────────────────────────────────────

fn classify_js(kind: &str) -> NodeRole {
    match kind {
        // ── Functions ────────────────────────────────────────────────────
        "function_declaration"
        | "function"
        | "async_function_declaration"
        | "generator_function_declaration" => NodeRole::Function {
            is_method: false,
            name_field: Some("name"),
            params_field: "parameters",
            body_field: "body",
        },
        "function_expression" | "async_function_expression" => NodeRole::Function {
            is_method: false,
            name_field: None,
            params_field: "parameters",
            body_field: "body",
        },
        "arrow_function" => NodeRole::Function {
            is_method: false,
            name_field: None,
            params_field: "parameters",
            body_field: "body",
        },
        "method_definition" => NodeRole::Function {
            is_method: true,
            name_field: Some("name"),
            params_field: "parameters",
            body_field: "body",
        },

        // ── Declarations / assignments ───────────────────────────────────
        "variable_declarator" | "lexical_declarator" => NodeRole::Declaration {
            name_field: "name",
            value_field: "value",
        },
        "assignment_expression" => NodeRole::Assignment {
            lhs_field: "left",
            rhs_field: "right",
        },

        // ── Calls ────────────────────────────────────────────────────────
        "call_expression" | "new_expression" => NodeRole::Call {
            callee_field: "function",
            args_field: "arguments",
        },
        "member_expression" => NodeRole::MemberAccess {
            object_field: "object",
            property_field: "property",
        },
        "subscript_expression" => NodeRole::MemberAccess {
            object_field: "object",
            property_field: "index",
        },

        // ── Control flow ─────────────────────────────────────────────────
        "if_statement" | "ternary_expression" | "switch_statement" => NodeRole::Branch,
        "for_statement" | "for_in_statement" | "for_of_statement" | "while_statement"
        | "do_statement" => NodeRole::Loop,
        "return_statement" => NodeRole::Return,
        "try_statement" => NodeRole::Try,
        "catch_clause" => NodeRole::Catch,
        "finally_clause" => NodeRole::Finally,
        "throw_statement" => NodeRole::Throw,
        "await_expression" => NodeRole::Await,

        // ── Structural ───────────────────────────────────────────────────
        "statement_block" | "object" => NodeRole::Block,
        "import_statement" => NodeRole::Import,
        "export_statement" => NodeRole::Export,
        "identifier" | "property_identifier" | "shorthand_property_identifier" => {
            NodeRole::Identifier
        }
        "string" | "template_string" | "number" | "true" | "false" | "null" | "undefined" => {
            NodeRole::Literal
        }

        _ => NodeRole::Other,
    }
}

fn extract_js_imports<'tree>(root: Node<'tree>, source: &str) -> Vec<Import> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();

        if node.kind() == "import_statement" {
            // `import defaultExport from "module"`
            // `import { named, other as alias } from "module"`
            // `import * as ns from "module"`
            let package = find_string_child(node, source)
                .unwrap_or_default()
                .trim_matches(['"', '\''])
                .to_owned();

            for i in 0..node.named_child_count() {
                let child = node.named_child(i).unwrap();
                match child.kind() {
                    "identifier" => {
                        // default import
                        imports.push(Import {
                            local_name: node_text(child, source).to_owned(),
                            package: package.clone(),
                            symbol: None,
                        });
                    }
                    "import_clause" => {
                        extract_import_clause(child, source, &package, &mut imports);
                    }
                    _ => {}
                }
            }
        }

        if node.kind() == "call_expression" {
            // `require("module")` and `require("module").something`
            if let Some(callee) = node.child_by_field_name("function") {
                if node_text(callee, source) == "require" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if let Some(str_node) = args.named_child(0) {
                            let pkg = node_text(str_node, source)
                                .trim_matches(['"', '\''])
                                .to_owned();
                            // The binding name comes from the outer variable_declarator
                            // We push a placeholder; the fingerprinter resolves it
                            // from the parent `variable_declarator.name` field.
                            imports.push(Import {
                                local_name: pkg.rsplit('/').next().unwrap_or(&pkg).to_owned(),
                                package: pkg,
                                symbol: None,
                            });
                        }
                    }
                }
            }
        }

        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                break 'outer;
            }
        }
    }

    imports
}

fn extract_import_clause(node: Node<'_>, source: &str, package: &str, out: &mut Vec<Import>) {
    for i in 0..node.named_child_count() {
        let child = node.named_child(i).unwrap();
        match child.kind() {
            "identifier" => {
                // `import { Foo }` — no alias
                out.push(Import {
                    local_name: node_text(child, source).to_owned(),
                    package: package.to_owned(),
                    symbol: Some(node_text(child, source).to_owned()),
                });
            }
            "import_specifier" => {
                // `import { Foo as Bar }` → local=Bar, symbol=Foo
                let name = child
                    .child_by_field_name("name")
                    .map(|n| node_text(n, source))
                    .unwrap_or("");
                let alias = child
                    .child_by_field_name("alias")
                    .map(|n| node_text(n, source))
                    .unwrap_or(name);
                out.push(Import {
                    local_name: alias.to_owned(),
                    package: package.to_owned(),
                    symbol: Some(name.to_owned()),
                });
            }
            "namespace_import" => {
                // `import * as ns`
                if let Some(id) = child.named_child(0) {
                    out.push(Import {
                        local_name: node_text(id, source).to_owned(),
                        package: package.to_owned(),
                        symbol: None,
                    });
                }
            }
            _ => {}
        }
    }
}

fn find_string_child<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    for i in 0..node.named_child_count() {
        let child = node.named_child(i)?;
        if matches!(child.kind(), "string" | "template_string") {
            return Some(node_text(child, source));
        }
    }
    None
}

// ── Package knowledge ─────────────────────────────────────────────────────────

fn js_package_category(pkg: &str) -> Option<PackageCategory> {
    // Normalize: strip @scope prefix for lookup, handle sub-paths
    let base = pkg.split('/').next().unwrap_or(pkg);
    match base {
        // HTTP frameworks
        "express" | "fastify" | "koa" | "hapi" | "@hono" | "hono" | "polka" | "h3" | "elysia"
        | "next" | "nuxt" | "@nestjs" | "nest" | "@adonisjs" => {
            Some(PackageCategory::HttpFramework)
        }

        // SQL
        "pg" | "postgres" | "mysql" | "mysql2" | "mariadb" | "sqlite3" | "better-sqlite3"
        | "mssql" | "oracledb" | "sequelize" | "knex" | "typeorm" | "@prisma" | "prisma"
        | "slonik" | "drizzle-orm" => Some(PackageCategory::SqlDatabase),

        // NoSQL
        "mongodb" | "mongoose" | "redis" | "ioredis" | "cassandra-driver" | "couchdb"
        | "@elastic" => Some(PackageCategory::NoSqlDatabase),

        // Command execution
        "child_process" | "shelljs" | "execa" | "cross-spawn" | "node-pty" | "spawn-command" => {
            Some(PackageCategory::CommandExecution)
        }

        // HTTP clients (SSRF)
        "node-fetch" | "axios" | "got" | "superagent" | "undici" | "request" | "node:http"
        | "node:https" => Some(PackageCategory::HttpClient),

        // File system (path traversal)
        "fs" | "node:fs" | "fs-extra" | "graceful-fs" | "recursive-readdir" | "glob" | "rimraf" => {
            Some(PackageCategory::FileSystem)
        }

        // Template engines (SSTI / XSS)
        "ejs" | "pug" | "handlebars" | "nunjucks" | "mustache" | "dot" | "art-template"
        | "consolidate" => Some(PackageCategory::TemplateEngine),

        // Unsafe deserialization
        "node-serialize" | "serialize-javascript" | "js-yaml" | "yaml" => {
            Some(PackageCategory::Deserialization)
        }

        _ => None,
    }
}

fn js_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        // HTML escape
        "escape" | "escapeHtml" | "escapeHTML" | "encodeHTML" | "sanitizeHtml" | "sanitize"
        | "clean" => Some(SanitizerKind::HtmlEscape),

        // URL encode
        "encodeURIComponent" | "encodeURI" | "encode" => Some(SanitizerKind::UrlEncode),

        // Numeric coercion — input is definitely a number after this
        "parseInt" | "parseFloat" | "Number" | "BigInt" | "toFixed" | "toPrecision" => {
            Some(SanitizerKind::Full)
        }

        // SQL parameterization (knex, sequelize, pg style)
        "sqlEscape" | "escapeId" | "format" | "literal" | "raw" => {
            Some(SanitizerKind::SqlParameterize)
        }

        // Path canonicalization
        "normalize" | "resolve" | "realpath" => Some(SanitizerKind::PathNormalize),

        _ => None,
    }
}

static JS_PROPAGATORS: &[PropagatorRule] = &[
    // String methods — receiver taints return
    PropagatorRule {
        call: "concat",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "replace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "replaceAll",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "slice",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "substring",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trim",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trimStart",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trimEnd",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "toLowerCase",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "toUpperCase",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "split",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "toString",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "padStart",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "padEnd",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // Array methods — receiver taints return
    PropagatorRule {
        call: "map",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "filter",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "flatMap",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "reduce",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "flat",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // JSON
    PropagatorRule {
        call: "parse",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "stringify",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Buffer / encoding
    PropagatorRule {
        call: "from",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "toString",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "atob",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "btoa",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "decodeURIComponent",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "encodeURIComponent",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Template tags
    PropagatorRule {
        call: "format",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "template",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "render",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Path manipulation
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "resolve",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "normalize",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
];

// ── TypeScript spec ───────────────────────────────────────────────────────────

pub struct TypeScriptSpec;

impl LanguageSpec for TypeScriptSpec {
    fn name(&self) -> &'static str {
        "typescript"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["ts", "tsx", "mts", "cts"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "typescript")]
        return tree_sitter_typescript::LANGUAGE_TSX.into();
        #[cfg(not(feature = "typescript"))]
        panic!("frensense-lang: 'typescript' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_js(kind)
    }

    fn wrap_region(&self, code: &str) -> String {
        format!("function _region(): void {{\n{}\n}}", code)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["import_statement"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_js_imports(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(
            r#"
            (function_declaration name: (identifier) @name)
            (method_definition name: (property_identifier) @name)
            (class_declaration name: (type_identifier) @name)
            (interface_declaration name: (type_identifier) @name)
            (variable_declarator name: (identifier) @name)
        "#,
        )
    }

    fn call_query(&self) -> Option<&'static str> {
        Some(
            r#"
            (function_declaration name: (identifier) @caller
                body: (statement_block
                    (expression_statement
                        (call_expression function: (identifier) @call))))
            (function_declaration name: (identifier) @caller
                body: (statement_block
                    (expression_statement
                        (call_expression
                            function: (member_expression
                                property: (property_identifier) @call)))))
            (method_definition name: (property_identifier) @caller
                body: (statement_block
                    (expression_statement
                        (call_expression function: (identifier) @call))))
        "#,
        )
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        js_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        classify_js_param(name, type_annotation)
    }

    fn is_http_route_decorator(&self, decorator_name: &str) -> bool {
        matches!(
            decorator_name,
            "Get"
                | "Post"
                | "Put"
                | "Delete"
                | "Patch"
                | "All"
                | "Controller"
                | "Route"
                | "HttpGet"
                | "HttpPost"
                | "UseGuards"
                | "UseInterceptors"
        )
    }

    fn request_param_names(&self) -> &'static [&'static str] {
        &["req", "request", "ctx", "context", "event", "c", "e"]
    }

    fn known_sink_names(&self) -> &'static [(&'static str, &'static str)] {
        JS_SINK_NAMES
    }

    fn known_source_patterns(&self) -> &'static [&'static str] {
        JS_SOURCE_PATTERNS
    }

    fn propagator_rules(&self) -> &'static [PropagatorRule] {
        JS_PROPAGATORS
    }

    fn classify_sanitizer(&self, call: &str) -> Option<SanitizerKind> {
        js_classify_sanitizer(call)
    }

    fn route_context_hints(&self) -> &'static [&'static str] {
        &[
            "(req, res)",
            "app.get(",
            "router.get(",
            "app.post(",
            "router.post(",
            "res.send",
            "res.json",
            "res.status",
            "c.req",
            "c.json",
            "ctx.body",
            "ctx.response",
            "fastify.get(",
            "fastify.post(",
        ]
    }

    fn test_context_hints(&self) -> &'static [&'static str] {
        &[
            "describe(",
            " it(",
            "test(",
            "expect(",
            "jest.",
            "vitest.",
            "chai.",
            "assert.",
        ]
    }

    fn response_method_names(&self) -> &'static [&'static str] {
        &[
            "json",
            "send",
            "redirect",
            "status",
            "render",
            "end",
            "write",
            "setHeader",
            "cookie",
            "clearCookie",
            "type",
            "format",
            "attachment",
        ]
    }

    fn db_api_method_names(&self) -> &'static [&'static str] {
        &[
            "query",
            "execute",
            "prepare",
            "raw",
            "find",
            "findOne",
            "findMany",
            "insert",
            "update",
            "delete",
            "create",
            "save",
            "select",
            "from",
            "where",
            "join",
            "aggregate",
            "count",
            "transaction",
            "commit",
            "rollback",
            "upsert",
        ]
    }

    fn shell_api_method_names(&self) -> &'static [&'static str] {
        &[
            "exec",
            "spawn",
            "execFile",
            "execSync",
            "spawnSync",
            "system",
        ]
    }

    fn route_registration_patterns(&self) -> &'static [&'static str] {
        &[
            "app.get(",
            "app.post(",
            "app.put(",
            "app.delete(",
            "app.patch(",
            "router.get(",
            "router.post(",
            "fastify.get(",
            "hono.get(",
        ]
    }
}

// ── JavaScript spec ────────────────────────────────────────────────────────────

pub struct JavaScriptSpec;

impl LanguageSpec for JavaScriptSpec {
    fn name(&self) -> &'static str {
        "javascript"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["js", "jsx", "mjs", "cjs"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "javascript")]
        return tree_sitter_javascript::LANGUAGE.into();
        #[cfg(not(feature = "javascript"))]
        panic!("frensense-lang: 'javascript' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_js(kind)
    }

    fn wrap_region(&self, code: &str) -> String {
        format!("function _region() {{\n{}\n}}", code)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["import_statement"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_js_imports(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(
            r#"
            (function_declaration name: (identifier) @name)
            (method_definition name: (property_identifier) @name)
            (class_declaration name: (identifier) @name)
            (variable_declarator name: (identifier) @name)
        "#,
        )
    }
    fn call_query(&self) -> Option<&'static str> {
        TypeScriptSpec.call_query()
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        js_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        classify_js_param(name, type_annotation)
    }

    fn request_param_names(&self) -> &'static [&'static str] {
        TypeScriptSpec.request_param_names()
    }

    fn known_sink_names(&self) -> &'static [(&'static str, &'static str)] {
        JS_SINK_NAMES
    }

    fn known_source_patterns(&self) -> &'static [&'static str] {
        JS_SOURCE_PATTERNS
    }

    fn propagator_rules(&self) -> &'static [PropagatorRule] {
        JS_PROPAGATORS
    }

    fn classify_sanitizer(&self, call: &str) -> Option<SanitizerKind> {
        js_classify_sanitizer(call)
    }

    fn route_context_hints(&self) -> &'static [&'static str] {
        TypeScriptSpec.route_context_hints()
    }

    fn test_context_hints(&self) -> &'static [&'static str] {
        TypeScriptSpec.test_context_hints()
    }

    fn response_method_names(&self) -> &'static [&'static str] {
        TypeScriptSpec.response_method_names()
    }

    fn db_api_method_names(&self) -> &'static [&'static str] {
        TypeScriptSpec.db_api_method_names()
    }

    fn shell_api_method_names(&self) -> &'static [&'static str] {
        TypeScriptSpec.shell_api_method_names()
    }

    fn route_registration_patterns(&self) -> &'static [&'static str] {
        TypeScriptSpec.route_registration_patterns()
    }
}

// ── Shared JS/TS param classification ─────────────────────────────────────────

fn classify_js_param(name: Option<&str>, ann: Option<&str>) -> Option<TaintOrigin> {
    // Type annotation from an HTTP framework package → confirmed user input
    if let Some(a) = ann {
        let base = a
            .trim_start_matches(':')
            .trim()
            .split(['<', '[', ' '])
            .next()
            .unwrap_or(a);
        let base = base.rsplit('.').next().unwrap_or(base);
        if matches!(
            base,
            "Request"
                | "IncomingMessage"
                | "FastifyRequest"
                | "Context"
                | "HonoContext"
                | "KoaContext"
                | "APIGatewayProxyEvent"
                | "HttpRequest"
        ) {
            return Some(TaintOrigin::UserInput);
        }
    }
    // Name-based fallback for untyped code
    match name? {
        "req" | "request" | "ctx" | "context" | "event" | "c" | "e" => Some(TaintOrigin::UserInput),
        _ => None,
    }
}

// ── Static sink/source tables ─────────────────────────────────────────────────

static JS_SINK_NAMES: &[(&str, &str)] = &[
    // Code Execution
    ("eval", "CodeExecution"),
    ("Function", "CodeExecution"),
    ("setTimeout", "CodeExecution"),
    ("setInterval", "CodeExecution"),
    ("runInNewContext", "CodeExecution"),
    ("runInThisContext", "CodeExecution"),
    ("require", "CodeExecution"),
    ("import", "CodeExecution"),
    // Command Injection
    ("exec", "CommandInjection"),
    ("execSync", "CommandInjection"),
    ("spawn", "CommandInjection"),
    ("spawnSync", "CommandInjection"),
    ("execFile", "CommandInjection"),
    ("execFileSync", "CommandInjection"),
    ("shelljs.exec", "CommandInjection"),
    ("execa", "CommandInjection"),
    // SQL Injection
    ("query", "SqlInjection"),
    ("execute", "SqlInjection"),
    ("executeRaw", "SqlInjection"),
    ("queryRaw", "SqlInjection"),
    ("raw", "SqlInjection"),
    ("prepare", "SqlInjection"),
    // Path Traversal
    ("readFile", "PathTraversal"),
    ("readFileSync", "PathTraversal"),
    ("createReadStream", "PathTraversal"),
    ("writeFile", "PathTraversal"),
    ("join", "PathTraversal"),
    ("unlink", "PathTraversal"),
    ("stat", "PathTraversal"),
    ("access", "PathTraversal"),
    // SSRF
    ("fetch", "Ssrf"),
    ("axios.get", "Ssrf"),
    ("axios.post", "Ssrf"),
    ("http.get", "Ssrf"),
    ("https.get", "Ssrf"),
    ("got", "Ssrf"),
    ("get", "Ssrf"),
    ("post", "Ssrf"),
    ("request", "Ssrf"),
    ("node-fetch", "Ssrf"),
    // Open Redirect
    ("redirect", "OpenRedirect"),
    ("location.href", "OpenRedirect"),
    ("window.location", "OpenRedirect"),
    // XSS
    ("innerHTML", "XssDom"),
    ("outerHTML", "XssDom"),
    ("document.write", "XssDom"),
    ("document.writeln", "XssDom"),
    ("dangerouslySetInnerHTML", "XssDom"),
    // MongoDB / ORM
    ("update", "NoSqlInjection"),
    ("updateOne", "NoSqlInjection"),
    ("updateMany", "NoSqlInjection"),
    ("insert", "NoSqlInjection"),
    ("insertOne", "NoSqlInjection"),
    ("insertMany", "NoSqlInjection"),
    ("delete", "NoSqlInjection"),
    ("deleteOne", "NoSqlInjection"),
    ("deleteMany", "NoSqlInjection"),
    ("find", "NoSqlInjection"),
    ("findOne", "NoSqlInjection"),
    ("findAll", "NoSqlInjection"),
    // Storage Write
    ("put", "StorageWrite"),
    ("setItem", "StorageWrite"),
    // Log Leak
    ("log", "LogLeak"),
    ("error", "LogLeak"),
    ("info", "LogLeak"),
    ("debug", "LogLeak"),
    // SSTI — Template engine renders
    ("ejs.render", "TemplateSsti"),
    ("ejs.renderFile", "TemplateSsti"),
    ("pug.compile", "TemplateSsti"),
    ("pug.render", "TemplateSsti"),
    ("handlebars.compile", "TemplateSsti"),
    ("handlebars.render", "TemplateSsti"),
    ("nunjucks.render", "TemplateSsti"),
    ("nunjucks.renderString", "TemplateSsti"),
    ("nunjucks.renderFile", "TemplateSsti"),
    ("marko.render", "TemplateSsti"),
    ("eta.render", "TemplateSsti"),
    ("swig.render", "TemplateSsti"),
    ("liquid.render", "TemplateSsti"),
    ("mustache.render", "TemplateSsti"),
    ("jade.render", "TemplateSsti"),
    ("react-dom/server.renderToString", "TemplateSsti"),
    ("vue-server-renderer.renderToString", "TemplateSsti"),
    // Insecure Deserialization
    ("serialize", "UnsafeDeserialize"),
    ("deserialize", "UnsafeDeserialize"),
    ("yaml.load", "UnsafeDeserialize"),
    ("js-yaml.load", "UnsafeDeserialize"),
    ("msgpack.decode", "UnsafeDeserialize"),
    ("msgpack.unpack", "UnsafeDeserialize"),
    // Prototype Pollution
    ("Object.assign", "PrototypePollution"),
    ("_.merge", "PrototypePollution"),
    ("lodash.merge", "PrototypePollution"),
    ("_.defaultsDeep", "PrototypePollution"),
    ("_.set", "PrototypePollution"),
    ("$.extend", "PrototypePollution"),
    ("jQuery.extend", "PrototypePollution"),
    ("angular.merge", "PrototypePollution"),
    ("setPrototypeOf", "PrototypePollution"),
    // XXE
    ("DOMParser", "Xxe"),
    // JWT
    ("jwt.verify", "Jwt"),
    ("jwt.decode", "Jwt"),
    ("jwt.sign", "Jwt"),
    ("jsonwebtoken.verify", "Jwt"),
    ("jsonwebtoken.decode", "Jwt"),
    ("jsonwebtoken.sign", "Jwt"),
    ("JWT.verify", "Jwt"),
    ("JWT.decode", "Jwt"),
    // Cloudflare Workers / Prisma
    ("c.redirect", "OpenRedirect"),
    ("env.KV.put", "StorageWrite"),
    ("KVNamespace.put", "StorageWrite"),
    ("KVNamespace.delete", "StorageWrite"),
    ("env.DB.prepare", "SqlInjection"),
    ("res.send", "ResponseLeak"),
    ("res.json", "ResponseLeak"),
    ("res.redirect", "OpenRedirect"),
    ("res.render", "TemplateSsti"),
    ("revalidatePath", "StorageWrite"),
    ("prisma.queryRawUnsafe", "SqlInjection"),
    ("prisma.executeRawUnsafe", "SqlInjection"),
    ("R2Bucket.put", "StorageWrite"),
    ("D1Database.prepare", "SqlInjection"),
    ("DurableObjectStub.fetch", "Ssrf"),
    ("Queue.send", "Ssrf"),
];

static JS_SOURCE_PATTERNS: &[&str] = &[
    "req.body",
    "req.query",
    "req.params",
    "req.headers",
    "req.cookies",
    "req.file",
    "req.files",
    "request.body",
    "request.query",
    "request.params",
    "ctx.request.body",
    "ctx.query",
    "ctx.params",
    "c.req.raw",
    "c.req.query",
    "c.req.param",
    "c.req",
    "event.body",
    "event.queryStringParameters",
    "event.pathParameters",
    "process.env",
    "process.argv",
    // Hardened for object destructuring: const { body, query, params } = req
    "body",
    "query",
    "params",
    "headers",
    "cookies",
    "file",
    "files",
];
