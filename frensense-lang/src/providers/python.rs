// SPDX-License-Identifier: MIT
//! Python [`LanguageSpec`] implementation.
//!
//! Key differences from JS/TS that broke the engine before this crate:
//! - Functions are `function_definition` / `async_function_definition`, not
//!   `function_declaration`. Both were silently skipped everywhere.
//! - Calls are `call` nodes, not `call_expression`.
//! - Member access is `attribute`, not `member_expression`.
//! - Assignments are `assignment`, not `variable_declarator`.
//! - `import_from_statement` (`from flask import Flask`) was never parsed.
//! - Route handlers are identified by decorators (`@app.route`), not param names.
//! - Python `with open(path) as f:` is a file-system sink that needs special handling.
//! - f-strings (`f"SELECT {user_input}"`) propagate taint through interpolation nodes.

use tree_sitter::Node;

use crate::spec::{
    call_last_segment, node_text, Import, LanguageSpec, NodeRole, PackageCategory, PropagatorRule,
    SanitizerKind, TaintOrigin,
};

// ── AST classification ────────────────────────────────────────────────────────

fn classify_python(kind: &str) -> NodeRole {
    match kind {
        // ── Functions ────────────────────────────────────────────────────
        // Both were missing from the engine's hardcoded match before this crate.
        "function_definition" | "async_function_definition" => NodeRole::Function {
            is_method: false, // determined by parent (class_definition body)
            name_field: Some("name"),
            params_field: "parameters",
            body_field: "body",
        },
        // `decorated_definition` wraps a `function_definition` with decorators.
        // Fingerprint extraction must descend into it to find the real function.
        // We classify it as a Function so the walker enters it.
        "decorated_definition" => NodeRole::Function {
            is_method: false,
            name_field: None, // name is on the inner function_definition
            params_field: "parameters",
            body_field: "body",
        },
        "lambda" => NodeRole::Function {
            is_method: false,
            name_field: None,
            params_field: "parameters",
            body_field: "body",
        },

        // ── Assignments ──────────────────────────────────────────────────
        // Python has no separate "declaration" concept — `x = expr` is both.
        "assignment" | "annotated_assignment" => NodeRole::Declaration {
            name_field: "left",
            value_field: "right",
        },
        "augmented_assignment" => NodeRole::Assignment {
            lhs_field: "left",
            rhs_field: "right",
        },
        // Walrus operator `:=` — e.g. `if (m := re.match(...))`
        "named_expression" => NodeRole::Declaration {
            name_field: "name",
            value_field: "value",
        },

        // ── Calls ────────────────────────────────────────────────────────
        // Python uses `call`, NOT `call_expression`
        "call" => NodeRole::Call {
            callee_field: "function",
            args_field: "arguments",
        },
        // Python member access is `attribute`, NOT `member_expression`
        "attribute" => NodeRole::MemberAccess {
            object_field: "object",
            property_field: "attribute",
        },
        "subscript" => NodeRole::MemberAccess {
            object_field: "value",
            property_field: "slice",
        },

        // ── Control flow ─────────────────────────────────────────────────
        "if_statement" | "conditional_expression" | "match_statement" => NodeRole::Branch,
        "for_statement" | "while_statement" => NodeRole::Loop,
        "return_statement" => NodeRole::Return,
        "try_statement" => NodeRole::Try,
        // Python uses `except_clause`, NOT `catch_clause`
        "except_clause" | "except_group_clause" => NodeRole::Catch,
        "finally_clause" => NodeRole::Finally,
        "raise_statement" => NodeRole::Throw,
        "await" => NodeRole::Await,
        // `with` statement — needs special context_manager_call handling
        "with_statement" => NodeRole::ContextManager,

        // ── Structural ───────────────────────────────────────────────────
        "block" => NodeRole::Block,
        "import_statement" | "import_from_statement" => NodeRole::Import,
        "identifier" => NodeRole::Identifier,
        "string" | "integer" | "float" | "true" | "false" | "none" | "concatenated_string" => {
            NodeRole::Literal
        }

        _ => NodeRole::Other,
    }
}

// ── Context manager sink detection ───────────────────────────────────────────

/// For `with open(path, mode) as f:`, extracts the path argument text
/// so the engine can check if it's tainted.
///
/// Returns `Some(path_text)` when the context manager is a file open call.
fn python_context_manager_call<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    if node.kind() != "with_statement" {
        return None;
    }

    // with_statement > with_clause > with_item > value (the expression)
    for i in 0..node.named_child_count() {
        let clause = node.named_child(i)?;
        for j in 0..clause.named_child_count() {
            let item = clause.named_child(j)?;
            if let Some(value) = item.child_by_field_name("value") {
                // Is it a call to `open`, `io.open`, `gzip.open`, etc.?
                if value.kind() == "call" {
                    if let Some(func) = value.child_by_field_name("function") {
                        let name = node_text(func, source);
                        let last = call_last_segment(name);
                        if matches!(last, "open" | "fopen" | "fdopen" | "gzip.open" | "bz2.open") {
                            // Return the first argument (the path)
                            if let Some(args) = value.child_by_field_name("arguments") {
                                if let Some(first_arg) = args.named_child(0) {
                                    return Some(node_text(first_arg, source));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// ── Import extraction ─────────────────────────────────────────────────────────

fn extract_python_imports(root: Node<'_>, source: &str) -> Vec<Import> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();

        match node.kind() {
            // `import flask`
            // `import sqlalchemy as sa`
            "import_statement" => {
                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        match child.kind() {
                            "dotted_name" => {
                                let pkg = node_text(child, source);
                                let local = pkg.split('.').next().unwrap_or(pkg);
                                imports.push(Import {
                                    local_name: local.to_owned(),
                                    package: pkg.to_owned(),
                                    symbol: None,
                                });
                            }
                            "aliased_import" => {
                                // `import sqlalchemy as sa`
                                let name = child
                                    .child_by_field_name("name")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or("");
                                let alias = child
                                    .child_by_field_name("alias")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or(name);
                                imports.push(Import {
                                    local_name: alias.to_owned(),
                                    package: name.to_owned(),
                                    symbol: None,
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }

            // `from flask import Flask, request`
            // `from flask import Flask as F`
            // `from sqlalchemy.orm import Session`
            "import_from_statement" => {
                let module_name = node
                    .child_by_field_name("module_name")
                    .map(|n| node_text(n, source))
                    .unwrap_or("")
                    .to_owned();

                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        match child.kind() {
                            "dotted_name" | "identifier" => {
                                let sym = node_text(child, source);
                                if sym != module_name.as_str() {
                                    imports.push(Import {
                                        local_name: sym.to_owned(),
                                        package: module_name.clone(),
                                        symbol: Some(sym.to_owned()),
                                    });
                                }
                            }
                            "aliased_import" => {
                                let name = child
                                    .child_by_field_name("name")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or("");
                                let alias = child
                                    .child_by_field_name("alias")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or(name);
                                imports.push(Import {
                                    local_name: alias.to_owned(),
                                    package: module_name.clone(),
                                    symbol: Some(name.to_owned()),
                                });
                            }
                            "wildcard_import" => {
                                // `from flask import *` — bind the module itself
                                imports.push(Import {
                                    local_name: module_name
                                        .split('.')
                                        .next()
                                        .unwrap_or(&module_name)
                                        .to_owned(),
                                    package: module_name.clone(),
                                    symbol: None,
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
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

// ── Package catalogue ─────────────────────────────────────────────────────────

fn python_package_category(pkg: &str) -> Option<PackageCategory> {
    // Match the top-level package name (before any `.`)
    let base = pkg.split('.').next().unwrap_or(pkg);
    match base {
        // ── HTTP frameworks ───────────────────────────────────────────────
        "flask" | "django" | "fastapi" | "aiohttp" | "tornado" | "starlette" | "sanic"
        | "falcon" | "bottle" | "pyramid" | "cherrypy" | "uvicorn" | "litestar" | "blacksheep"
        | "robyn" => Some(PackageCategory::HttpFramework),

        // ── SQL databases ─────────────────────────────────────────────────
        "sqlalchemy" | "psycopg2" | "psycopg" | "pymysql" | "sqlite3" | "pymssql" | "cx_Oracle"
        | "aiomysql" | "asyncpg" | "databases" | "tortoise" | "peewee" | "pony" => {
            Some(PackageCategory::SqlDatabase)
        }

        // ── NoSQL ─────────────────────────────────────────────────────────
        "pymongo" | "motor" | "redis" | "aioredis" | "elasticsearch" | "cassandra" | "couchdb" => {
            Some(PackageCategory::NoSqlDatabase)
        }

        // ── Command execution ─────────────────────────────────────────────
        "subprocess" | "os" | "shlex" | "pty" | "popen2" | "commands" | "plumbum" | "sh" => {
            Some(PackageCategory::CommandExecution)
        }

        // ── File system ───────────────────────────────────────────────────
        "pathlib" | "shutil" | "glob" | "tempfile" | "io" | "fileinput" | "zipfile" | "tarfile" => {
            Some(PackageCategory::FileSystem)
        }

        // ── HTTP clients (SSRF) ───────────────────────────────────────────
        "requests" | "httpx" | "urllib" | "urllib3" | "httplib2" | "pycurl" | "grequests" => {
            Some(PackageCategory::HttpClient)
        }

        // ── Template engines (SSTI) ───────────────────────────────────────
        "jinja2" | "mako" | "chameleon" | "genshi" => Some(PackageCategory::TemplateEngine), // also framework

        // ── Unsafe deserialization ────────────────────────────────────────
        "pickle" | "cPickle" | "shelve" | "marshal" | "yaml" | "PyYAML" | "jsonpickle" | "dill" => {
            Some(PackageCategory::Deserialization)
        }

        // ── Crypto ───────────────────────────────────────────────────────
        "cryptography" | "Crypto" | "nacl" | "hashlib" | "hmac" | "secrets" => {
            Some(PackageCategory::Crypto)
        }

        // ── Testing ───────────────────────────────────────────────────────
        "pytest" | "unittest" | "nose" | "hypothesis" => Some(PackageCategory::Testing),

        _ => None,
    }
}

// ── Param taint ───────────────────────────────────────────────────────────────

fn python_classify_param(name: Option<&str>, ann: Option<&str>) -> Option<TaintOrigin> {
    // FastAPI: parameter type is a Pydantic model or an explicit annotation
    // like `request: Request`. The type annotation is the key signal.
    if let Some(a) = ann {
        let base = a.split('[').next().unwrap_or(a).trim();
        if matches!(base, "Request" | "HTTPRequest" | "HttpRequest") {
            return Some(TaintOrigin::UserInput);
        }
        // FastAPI dependencies annotated with `Query(...)`, `Path(...)`, `Body(...)`
        // These appear in function signatures as `param: str = Query(...)`.
        // We can't distinguish from annotation alone; handled by propagators.
    }

    // Flask / Django: `request` is always a global taint source — no param needed.
    // FastAPI: named params from URL path / query are taint sources by framework convention.
    match name? {
        "request" | "req" => Some(TaintOrigin::UserInput),
        _ => None,
    }
}

// ── Sanitizers ────────────────────────────────────────────────────────────────

fn python_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        // Numeric coercion
        "int" | "float" | "bool" | "abs" | "round" => Some(SanitizerKind::Full),
        // HTML escaping (stdlib)
        "escape" | "html_escape" | "cgi_escape" => Some(SanitizerKind::HtmlEscape),
        // Bleach, MarkupSafe
        "clean" | "linkify" | "Markup" => Some(SanitizerKind::HtmlEscape),
        // URL encoding
        "quote" | "quote_plus" | "urlencode" => Some(SanitizerKind::UrlEncode),
        // Path normalization
        "realpath" | "abspath" | "normpath" | "normcase" => Some(SanitizerKind::PathNormalize),
        // SQL parameterization (SQLAlchemy `text()` with bound params)
        "text" | "literal" | "bindparam" => Some(SanitizerKind::SqlParameterize),
        _ => None,
    }
}

// ── Propagators ───────────────────────────────────────────────────────────────

static PYTHON_PROPAGATORS: &[PropagatorRule] = &[
    // str methods — receiver taints return
    PropagatorRule {
        call: "format",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "format_map",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "replace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "split",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "strip",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "lstrip",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "rstrip",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "lower",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "upper",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "title",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "encode",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "decode",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // Type coercions that propagate (not sanitize) taint
    PropagatorRule {
        call: "str",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "bytes",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "list",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "tuple",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "dict",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // json
    PropagatorRule {
        call: "loads",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "dumps",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // re / regex
    PropagatorRule {
        call: "sub",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "subn",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "group",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "groups",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // path building
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: false,
    },
    // f-string interpolation: `f"SELECT {user}"` is handled by the
    // flow_fingerprint's is_interpolation_node check, not propagator rules.
    // Listed here for documentation completeness.

    // % formatting: `"SELECT %s" % user` — treated as format propagation
    // This is a BinaryOp in the AST, not a call. The flow fingerprinter
    // checks for `binary_operator` with operator `%` and a tainted RHS.
];

// ── Tree-sitter queries ───────────────────────────────────────────────────────

const PYTHON_SYMBOL_QUERY: &str = r#"
    (function_definition name: (identifier) @name)
    (async_function_definition name: (identifier) @name)
    (class_definition name: (identifier) @name)
"#;

// Covers both top-level functions and class methods.
const PYTHON_CALL_QUERY: &str = r#"
    (function_definition name: (identifier) @caller
        body: (block
            (expression_statement
                (call function: (identifier) @call))))

    (function_definition name: (identifier) @caller
        body: (block
            (expression_statement
                (call function:
                    (attribute attribute: (identifier) @call)))))

    (class_definition body: (block
        (function_definition name: (identifier) @caller
            body: (block
                (expression_statement
                    (call function: (identifier) @call))))))

    (class_definition body: (block
        (function_definition name: (identifier) @caller
            body: (block
                (expression_statement
                    (call function:
                        (attribute attribute: (identifier) @call)))))))

    (async_function_definition name: (identifier) @caller
        body: (block
            (expression_statement
                (call function: (identifier) @call))))

    (async_function_definition name: (identifier) @caller
        body: (block
            (expression_statement
                (call function:
                    (attribute attribute: (identifier) @call)))))
"#;

// ── PythonSpec ────────────────────────────────────────────────────────────────

pub struct PythonSpec;

impl LanguageSpec for PythonSpec {
    fn name(&self) -> &'static str {
        "python"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["py", "pyi", "pyw"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "python")]
        return tree_sitter_python::LANGUAGE.into();
        #[cfg(not(feature = "python"))]
        panic!("frensense-lang: 'python' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_python(kind)
    }

    /// Python `with open(path) as f:` — extracts the path argument.
    fn context_manager_call<'s>(&self, node: Node<'_>, source: &'s str) -> Option<&'s str> {
        python_context_manager_call(node, source)
    }

    fn wrap_region(&self, code: &str) -> String {
        // Python requires indentation inside function bodies
        let indented: String = code.lines().map(|l| format!("    {}\n", l)).collect();
        format!("def _region():\n{}", indented)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["import_statement", "import_from_statement"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_python_imports(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(PYTHON_SYMBOL_QUERY)
    }
    fn call_query(&self) -> Option<&'static str> {
        Some(PYTHON_CALL_QUERY)
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        python_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        python_classify_param(name, type_annotation)
    }

    fn is_http_route_decorator(&self, name: &str) -> bool {
        // Matches the decorator name regardless of which framework uses it
        matches!(
            name,
            "route" | "get" | "post" | "put" | "delete" | "patch" | "options" | "head"
            // Django
            | "login_required" | "require_http_methods" | "require_GET" | "require_POST"
            // FastAPI
            | "router" | "api_route"
        )
    }

    fn request_param_names(&self) -> &'static [&'static str] {
        // Flask: `request` is a global import, not a parameter.
        // Django: view functions receive a `request` parameter.
        // FastAPI: `request: Request` is an explicit parameter.
        &["request", "req", "r"]
    }

    fn known_sink_names(&self) -> &'static [(&'static str, &'static str)] {
        &[
            // Code Execution
            ("eval", "CodeExecution"),
            ("exec", "CodeExecution"),
            ("compile", "CodeExecution"),
            // Command Injection
            ("system", "CommandInjection"),
            ("popen", "CommandInjection"),
            ("call", "CommandInjection"),
            ("run", "CommandInjection"),
            ("check_output", "CommandInjection"),
            ("Popen", "CommandInjection"),
            ("execfile", "CommandInjection"),
            ("spawn", "CommandInjection"),
            ("spawnSync", "CommandInjection"),
            // SQL Injection
            ("execute", "SqlInjection"),
            ("executemany", "SqlInjection"),
            ("raw", "SqlInjection"),
            ("raw_sql", "SqlInjection"),
            ("query", "SqlInjection"),
            ("executeRaw", "SqlInjection"),
            ("queryRaw", "SqlInjection"),
            ("filter", "SqlInjection"), // Django ORM raw filter
            ("extra", "SqlInjection"),  // Django ORM .extra()
            ("prepare", "SqlInjection"),
            // Path Traversal
            ("open", "PathTraversal"),
            ("read", "PathTraversal"),
            ("write", "PathTraversal"),
            ("readFile", "PathTraversal"),
            ("writeFile", "PathTraversal"),
            ("readFileSync", "PathTraversal"),
            ("join", "PathTraversal"),
            ("unlink", "PathTraversal"),
            ("stat", "PathTraversal"),
            ("access", "PathTraversal"),
            // SSRF
            ("get", "Ssrf"),
            ("post", "Ssrf"),
            ("request", "Ssrf"),
            ("send", "Ssrf"),
            ("fetch", "Ssrf"),
            ("http.get", "Ssrf"),
            ("https.get", "Ssrf"),
            ("got", "Ssrf"),
            // Open Redirect
            ("redirect", "OpenRedirect"),
            // XSS
            ("innerHTML", "XssDom"),
            ("outerHTML", "XssDom"),
            ("document.write", "XssDom"),
            ("dangerouslySetInnerHTML", "XssDom"),
            // SSTI — Template engine renders
            ("render_template", "TemplateSsti"),
            ("render_template_string", "TemplateSsti"),
            ("from_string", "TemplateSsti"),
            ("render", "TemplateSsti"),
            ("ejs.render", "TemplateSsti"),
            ("pug.compile", "TemplateSsti"),
            ("handlebars.compile", "TemplateSsti"),
            ("nunjucks.render", "TemplateSsti"),
            ("marko.render", "TemplateSsti"),
            ("eta.render", "TemplateSsti"),
            ("swig.render", "TemplateSsti"),
            ("liquid.render", "TemplateSsti"),
            ("mustache.render", "TemplateSsti"),
            // Response
            ("make_response", "XssReflected"),
            ("res.send", "ResponseLeak"),
            ("res.json", "ResponseLeak"),
            // Unsafe Deserialization
            ("pickle.loads", "UnsafeDeserialize"),
            ("pickle.load", "UnsafeDeserialize"),
            ("yaml.load", "UnsafeDeserialize"),
            ("yaml.safe_load", "UnsafeDeserialize"),
            ("marshal.loads", "UnsafeDeserialize"),
            ("shelve.open", "UnsafeDeserialize"),
            ("loads", "UnsafeDeserialize"),
            ("load", "UnsafeDeserialize"),
            ("bincode::deserialize", "UnsafeDeserialize"),
            // Log Leak
            ("log", "LogLeak"),
            ("error", "LogLeak"),
            ("info", "LogLeak"),
            ("debug", "LogLeak"),
            // Prototype Pollution
            ("Object.assign", "PrototypePollution"),
            ("_.merge", "PrototypePollution"),
            ("_.defaultsDeep", "PrototypePollution"),
            ("_.set", "PrototypePollution"),
            ("$.extend", "PrototypePollution"),
            ("setPrototypeOf", "PrototypePollution"),
            // XXE
            ("DOMParser", "Xxe"),
            // JWT
            ("jwt.verify", "Jwt"),
            ("jwt.decode", "Jwt"),
            ("jwt.sign", "Jwt"),
            // MongoDB / ORM operators
            ("$where", "NoSqlInjection"),
            ("$regex", "NoSqlInjection"),
            ("$gt", "NoSqlInjection"),
            ("$lt", "NoSqlInjection"),
            ("$ne", "NoSqlInjection"),
            ("$in", "NoSqlInjection"),
            ("$nin", "NoSqlInjection"),
            ("$exists", "NoSqlInjection"),
            ("$expr", "NoSqlInjection"),
            ("$function", "NoSqlInjection"),
            ("$accumulator", "NoSqlInjection"),
        ]
    }

    fn known_source_patterns(&self) -> &'static [&'static str] {
        &[
            // Flask
            "request.args",
            "request.form",
            "request.json",
            "request.data",
            "request.values",
            "request.files",
            "request.cookies",
            "request.headers",
            "request.get_json()",
            "request.get_data()",
            // Django
            "request.GET",
            "request.POST",
            "request.body",
            "request.META",
            "request.FILES",
            "request.COOKIES",
            // FastAPI — these are parameter names, recognised via classify_param_taint
            // but listed here for motif matching
            "Query",
            "Path",
            "Body",
            "Form",
            "Header",
            "Cookie",
            // aiohttp
            "request.match_info",
            "request.rel_url.query",
            "await request.json()",
            "await request.text()",
            "await request.read()",
            "await request.post()",
        ]
    }

    fn propagator_rules(&self) -> &'static [PropagatorRule] {
        PYTHON_PROPAGATORS
    }

    fn classify_sanitizer(&self, call: &str) -> Option<SanitizerKind> {
        python_classify_sanitizer(call)
    }

    fn route_context_hints(&self) -> &'static [&'static str] {
        &[
            "@app.route",
            "@router.get",
            "@router.post",
            "@bp.route",
            "@blueprint.route",
            "from flask import",
            "from fastapi import",
            "from django.http import",
            "from aiohttp import",
            "request.args",
            "request.form",
            "request.json",
            "request.GET",
            "request.POST",
            "return jsonify",
            "return Response",
            "return render_template",
            "return render(",
            "HttpResponse",
            "JsonResponse",
        ]
    }

    fn test_context_hints(&self) -> &'static [&'static str] {
        &[
            "import pytest",
            "def test_",
            "unittest.TestCase",
            "self.assert",
            "self.assertEqual",
            "pytest.raises",
            "from unittest",
            "@pytest.fixture",
            "@pytest.mark",
        ]
    }

    fn response_method_names(&self) -> &'static [&'static str] {
        &[
            "jsonify",
            "make_response",
            "render_template",
            "redirect",
            "Response",
        ]
    }

    fn db_api_method_names(&self) -> &'static [&'static str] {
        &[]
    }

    fn shell_api_method_names(&self) -> &'static [&'static str] {
        &[]
    }
}
