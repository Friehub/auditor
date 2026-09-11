// SPDX-License-Identifier: MIT
//! Go [`LanguageSpec`] implementation.
//!
//! Covers:
//! - `function_declaration` (top-level) AND `method_declaration` (the one that
//!   was silently skipped everywhere before this crate)
//! - `short_var_declaration` / `assignment_statement` (not `variable_declarator`)
//! - `selector_expression` for member access (not `member_expression`)
//! - `import_declaration` with alias and grouped imports
//! - `is_error_guard` for `if err != nil { return }` detection
//! - call_query covering both functions and method receivers
//! - Complete stdlib + major framework package catalogue

use tree_sitter::Node;

use crate::spec::{
    call_last_segment, node_text, Import, LanguageSpec, NodeRole, PackageCategory, PropagatorRule,
    SanitizerKind, TaintOrigin,
};

// ── AST classification ────────────────────────────────────────────────────────

fn classify_go(kind: &str) -> NodeRole {
    match kind {
        // ── Functions ────────────────────────────────────────────────────
        "function_declaration" => NodeRole::Function {
            is_method: false,
            name_field: Some("name"),
            params_field: "parameters",
            body_field: "body",
        },
        // This was the critical missing case — ALL Go struct methods
        "method_declaration" => NodeRole::Function {
            is_method: true,
            name_field: Some("name"),
            params_field: "parameters",
            body_field: "body",
        },
        "func_literal" => NodeRole::Function {
            is_method: false,
            name_field: None,
            params_field: "parameters",
            body_field: "body",
        },

        // ── Declarations / assignments ───────────────────────────────────
        // Go := operator — was missing everywhere in the engine before this crate
        "short_var_declaration" => NodeRole::Declaration {
            name_field: "left",
            value_field: "right",
        },
        // Go = operator (mutation of existing variable)
        "assignment_statement" => NodeRole::Assignment {
            lhs_field: "left",
            rhs_field: "right",
        },
        // var x type = expr  (top-level or function-scoped)
        "var_spec" => NodeRole::Declaration {
            name_field: "name",
            value_field: "value",
        },
        // const x = expr
        "const_spec" => NodeRole::Declaration {
            name_field: "name",
            value_field: "value",
        },

        // ── Calls ────────────────────────────────────────────────────────
        "call_expression" => NodeRole::Call {
            callee_field: "function",
            args_field: "arguments",
        },
        // pkg.Function or receiver.Method — NOT `member_expression`
        "selector_expression" => NodeRole::MemberAccess {
            object_field: "operand",
            property_field: "field",
        },

        // ── Control flow ─────────────────────────────────────────────────
        // Go uses a single `for` for loops, range, and while-style
        "for_statement" => NodeRole::Loop,
        "if_statement" => NodeRole::Branch,
        // type switch and expression switch
        "expression_switch_statement" | "type_switch_statement" => NodeRole::Branch,
        "return_statement" => NodeRole::Return,
        // Go has no try/catch — but defer/recover pattern exists
        "defer_statement" => NodeRole::Await, // closest analogue
        "go_statement" => NodeRole::Await,    // goroutine launch
        "send_statement" => NodeRole::Other,

        // ── Structural ───────────────────────────────────────────────────
        "block" => NodeRole::Block,
        "import_declaration" | "import_spec" => NodeRole::Import,
        "identifier" | "field_identifier" | "type_identifier" | "blank_identifier" => {
            NodeRole::Identifier
        }
        "interpreted_string_literal"
        | "raw_string_literal"
        | "int_literal"
        | "float_literal"
        | "rune_literal" => NodeRole::Literal,

        _ => NodeRole::Other,
    }
}

// ── Error guard detection ─────────────────────────────────────────────────────

/// Returns `true` for `if err != nil { … }` and common variants.
///
/// This is Go's primary error-propagation pattern and must be recognised by the
/// CFG builder so it can emit exception-like edges rather than plain branches.
fn go_is_error_guard(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "if_statement" {
        return false;
    }
    let Some(cond) = node.child_by_field_name("condition") else {
        return false;
    };
    let cond_text = node_text(cond, source);
    // Matches: `err != nil`, `err == nil` (early return on success),
    // `err != nil && err != io.EOF`, custom error variable names like `dbErr`
    (cond_text.contains("err") || cond_text.contains("Err") || cond_text.contains("error"))
        && (cond_text.contains("nil")
            || cond_text.contains("!= nil")
            || cond_text.contains("== nil"))
}

// ── Import extraction ─────────────────────────────────────────────────────────

fn extract_go_imports(root: Node<'_>, source: &str) -> Vec<Import> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();

        match node.kind() {
            // import "path" or import alias "path"
            "import_spec" => {
                let path_node = node.child_by_field_name("path");
                let name_node = node.child_by_field_name("name"); // optional alias

                if let Some(path_n) = path_node {
                    let raw = node_text(path_n, source).trim_matches('"');
                    // Go package convention: local name = last path segment
                    // unless an explicit alias is given
                    let default_local = raw.rsplit('/').next().unwrap_or(raw);
                    let local = name_node
                        .map(|n| node_text(n, source))
                        .filter(|s| *s != "_" && *s != ".")
                        .unwrap_or(default_local);

                    imports.push(Import {
                        local_name: local.to_owned(),
                        package: raw.to_owned(),
                        symbol: None,
                    });
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

fn go_package_category(pkg: &str) -> Option<PackageCategory> {
    // Exact stdlib or well-known module path match
    match pkg {
        // ── HTTP frameworks ───────────────────────────────────────────────
        "net/http"
        | "github.com/gin-gonic/gin"
        | "github.com/labstack/echo/v4"
        | "github.com/labstack/echo/v5"
        | "github.com/gofiber/fiber/v2"
        | "github.com/go-chi/chi/v5"
        | "github.com/go-chi/chi"
        | "github.com/gorilla/mux"
        | "github.com/julienschmidt/httprouter"
        | "github.com/valyala/fasthttp" => Some(PackageCategory::HttpFramework),

        // ── SQL databases ─────────────────────────────────────────────────
        "database/sql"
        | "github.com/jmoiron/sqlx"
        | "gorm.io/gorm"
        | "github.com/go-gorm/gorm"
        | "github.com/uptrace/bun"
        | "github.com/lib/pq"
        | "github.com/go-sql-driver/mysql"
        | "modernc.org/sqlite"
        | "github.com/mattn/go-sqlite3"
        | "github.com/jackc/pgx/v5"
        | "github.com/jackc/pgx/v4" => Some(PackageCategory::SqlDatabase),

        // ── NoSQL ─────────────────────────────────────────────────────────
        "go.mongodb.org/mongo-driver/mongo"
        | "github.com/go-redis/redis/v8"
        | "github.com/redis/go-redis/v9"
        | "github.com/elastic/go-elasticsearch/v8" => Some(PackageCategory::NoSqlDatabase),

        // ── Command execution ─────────────────────────────────────────────
        "os/exec" => Some(PackageCategory::CommandExecution),

        // ── File system ───────────────────────────────────────────────────
        "os" | "io" | "io/ioutil" | "path/filepath" | "path" => Some(PackageCategory::FileSystem),

        // ── HTTP clients (SSRF) ───────────────────────────────────────────
        // "net/http"              // doubles as client
        | "github.com/go-resty/resty/v2"
        | "github.com/hashicorp/go-retryablehttp" => Some(PackageCategory::HttpClient),

        // ── Template engines (SSTI) ───────────────────────────────────────
        "html/template" | "text/template" => Some(PackageCategory::TemplateEngine),

        // ── Deserialization ───────────────────────────────────────────────
        "encoding/json"  // standard, usually safe but flag unsafe use
        | "gopkg.in/yaml.v3"
        | "gopkg.in/yaml.v2"
        | "github.com/BurntSushi/toml" => Some(PackageCategory::Deserialization),

        _ => None,
    }
}

// ── Param taint ───────────────────────────────────────────────────────────────

fn go_classify_param(name: Option<&str>, ann: Option<&str>) -> Option<TaintOrigin> {
    // Type annotation: `*http.Request`, `*gin.Context`, `echo.Context`, etc.
    if let Some(a) = ann {
        let a = a.trim_start_matches('*'); // remove pointer indirection
        if a.ends_with("http.Request")
            || a.ends_with("gin.Context")
            || a.ends_with("echo.Context")
            || a.ends_with("fiber.Ctx")
            || a.ends_with("chi.Context")
            || a.ends_with(".Request")
        // covers any framework's Request type
        {
            return Some(TaintOrigin::UserInput);
        }
    }
    // Name-based fallback: Go convention uses `r` for *http.Request
    match name? {
        "r" | "req" | "c" | "ctx" | "w" => Some(TaintOrigin::UserInput),
        _ => None,
    }
}

// ── Sanitizers ────────────────────────────────────────────────────────────────

fn go_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        // Numeric coercion — kills injection risk
        "Atoi" | "ParseInt" | "ParseUint" | "ParseFloat" | "ParseBool" => Some(SanitizerKind::Full),
        // HTML escaping
        "EscapeString" | "HTMLEscapeString" | "HTMLEscape" => Some(SanitizerKind::HtmlEscape),
        // URL encoding
        "QueryEscape" | "PathEscape" | "PathUnescape" => Some(SanitizerKind::UrlEncode),
        // Path cleaning — partial mitigation for path traversal
        "Clean" | "Abs" | "EvalSymlinks" => Some(SanitizerKind::PathNormalize),
        _ => None,
    }
}

// ── Propagators ───────────────────────────────────────────────────────────────

static GO_PROPAGATORS: &[PropagatorRule] = &[
    // fmt — format string propagates taint from args
    PropagatorRule {
        call: "Sprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Fprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Errorf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Stringer",
        tainted_arg: None,
        tainted_receiver: false,
    },
    // strings — receiver taints return
    PropagatorRule {
        call: "Join",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "Replace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "ReplaceAll",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "TrimSpace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "Trim",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "ToLower",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "ToUpper",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Split",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "SplitN",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Contains",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "HasPrefix",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "HasSuffix",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // strconv — propagates taint (type conversion, not sanitization)
    PropagatorRule {
        call: "Itoa",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "FormatInt",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "AppendInt",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // path/filepath — path building propagates traversal risk
    PropagatorRule {
        call: "Join",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Base",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // bytes.Buffer / strings.Builder
    PropagatorRule {
        call: "WriteString",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "Write",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "String",
        tainted_arg: None,
        tainted_receiver: true,
    },
];

// ── Tree-sitter queries ───────────────────────────────────────────────────────

const GO_SYMBOL_QUERY: &str = r#"
    (function_declaration name: (identifier) @name)
    (method_declaration   name: (field_identifier) @name)
    (type_declaration
        (type_spec name: (type_identifier) @name))
    (var_declaration
        (var_spec name: (identifier) @name))
    (const_declaration
        (const_spec name: (identifier) @name))
"#;

// Captures call edges for the interprocedural call graph.
// Two patterns: direct identifier calls and selector (pkg/receiver method) calls.
const GO_CALL_QUERY: &str = r#"
    (function_declaration name: (identifier) @caller
        body: (block
            (expression_statement
                (call_expression function: (identifier) @call))))

    (function_declaration name: (identifier) @caller
        body: (block
            (expression_statement
                (call_expression
                    function: (selector_expression
                        field: (field_identifier) @call)))))

    (method_declaration name: (field_identifier) @caller
        body: (block
            (expression_statement
                (call_expression function: (identifier) @call))))

    (method_declaration name: (field_identifier) @caller
        body: (block
            (expression_statement
                (call_expression
                    function: (selector_expression
                        field: (field_identifier) @call)))))

    (function_declaration name: (identifier) @caller
        body: (block
            (short_var_declaration
                right: (call_expression function: (identifier) @call))))

    (function_declaration name: (identifier) @caller
        body: (block
            (short_var_declaration
                right: (call_expression
                    function: (selector_expression
                        field: (field_identifier) @call)))))
"#;

// ── GoSpec ────────────────────────────────────────────────────────────────────

pub struct GoSpec;

impl LanguageSpec for GoSpec {
    fn name(&self) -> &'static str {
        "go"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["go"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "go")]
        return tree_sitter_go::LANGUAGE.into();
        #[cfg(not(feature = "go"))]
        panic!("frensense-lang: 'go' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_go(kind)
    }

    /// Go-specific: detect `if err != nil { return … }`.
    fn is_error_guard<'tree>(&self, node: Node<'tree>, source: &str) -> bool {
        go_is_error_guard(node, source)
    }

    fn wrap_region(&self, code: &str) -> String {
        format!("func _region() {{\n{}\n}}", code)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["import_declaration", "import_spec"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_go_imports(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(GO_SYMBOL_QUERY)
    }
    fn call_query(&self) -> Option<&'static str> {
        Some(GO_CALL_QUERY)
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        go_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        go_classify_param(name, type_annotation)
    }

    fn is_http_route_decorator(&self, _: &str) -> bool {
        // Go has no decorator syntax; route registration is detected via
        // route_context_hints and the SemanticProvider's call analysis.
        false
    }

    fn request_param_names(&self) -> &'static [&'static str] {
        // Convention: r=*http.Request, w=http.ResponseWriter, c=*gin.Context
        &["r", "req", "c", "ctx", "w"]
    }

    fn known_sink_names(&self) -> &'static [(&'static str, &'static str)] {
        &[
            // Code Execution
            ("eval", "CodeExecution"),
            ("exec", "CommandInjection"),
            ("Exec", "CommandInjection"),
            ("Command", "CommandInjection"),
            ("Run", "CommandInjection"),
            ("Output", "CommandInjection"),
            ("CombinedOutput", "CommandInjection"),
            ("spawn", "CommandInjection"),
            ("spawnSync", "CommandInjection"),
            // SQL Injection
            ("Query", "SqlInjection"),
            ("QueryRow", "SqlInjection"),
            ("QueryContext", "SqlInjection"),
            ("ExecContext", "SqlInjection"),
            ("Prepare", "SqlInjection"),
            ("PrepareContext", "SqlInjection"),
            ("executeRaw", "SqlInjection"),
            ("queryRaw", "SqlInjection"),
            ("prepare", "SqlInjection"),
            // Path Traversal
            ("ReadFile", "PathTraversal"),
            ("Open", "PathTraversal"),
            ("Create", "PathTraversal"),
            ("WriteFile", "PathTraversal"),
            ("read", "PathTraversal"),
            ("read_to_string", "PathTraversal"),
            ("write", "PathTraversal"),
            ("readFile", "PathTraversal"),
            ("writeFile", "PathTraversal"),
            ("readFileSync", "PathTraversal"),
            ("join", "PathTraversal"),
            ("unlink", "PathTraversal"),
            ("stat", "PathTraversal"),
            ("access", "PathTraversal"),
            // SSRF
            ("http.Get", "Ssrf"),
            ("http.Post", "Ssrf"),
            ("http.Head", "Ssrf"),
            ("http.Do", "Ssrf"),
            ("Get", "Ssrf"),
            ("Post", "Ssrf"),
            ("Do", "Ssrf"),
            ("NewRequest", "Ssrf"),
            ("fetch", "Ssrf"),
            ("request", "Ssrf"),
            ("got", "Ssrf"),
            // Open Redirect
            ("redirect", "OpenRedirect"),
            ("Redirect", "OpenRedirect"),
            ("c.redirect", "OpenRedirect"),
            ("location.href", "OpenRedirect"),
            ("window.location", "OpenRedirect"),
            // XSS
            ("innerHTML", "XssDom"),
            ("outerHTML", "XssDom"),
            ("document.write", "XssDom"),
            ("document.writeln", "XssDom"),
            ("dangerouslySetInnerHTML", "XssDom"),
            // SSTI — Template engine renders
            ("ExecuteTemplate", "TemplateSsti"),
            ("render_template", "TemplateSsti"),
            ("render_template_string", "TemplateSsti"),
            ("ejs.render", "TemplateSsti"),
            ("pug.compile", "TemplateSsti"),
            ("handlebars.compile", "TemplateSsti"),
            ("nunjucks.render", "TemplateSsti"),
            ("marko.render", "TemplateSsti"),
            ("eta.render", "TemplateSsti"),
            ("swig.render", "TemplateSsti"),
            ("liquid.render", "TemplateSsti"),
            ("mustache.render", "TemplateSsti"),
            // Insecure Deserialization
            ("bincode::deserialize", "UnsafeDeserialize"),
            ("serde_json::from_str", "UnsafeDeserialize"),
            ("yaml.load", "UnsafeDeserialize"),
            ("js-yaml.load", "UnsafeDeserialize"),
            ("pickle.loads", "UnsafeDeserialize"),
            ("msgpack.decode", "UnsafeDeserialize"),
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
            // Cloudflare Workers / Prisma
            ("c.redirect", "OpenRedirect"),
            ("env.KV.put", "StorageWrite"),
            ("KVNamespace.put", "StorageWrite"),
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
        ]
    }

    fn known_source_patterns(&self) -> &'static [&'static str] {
        &[
            // net/http standard library
            "r.URL.Query",
            "r.URL.Path",
            "r.URL.RawQuery",
            "r.FormValue",
            "r.PostFormValue",
            "r.Body",
            "r.Header.Get",
            "r.PathValue",
            // Gin
            "c.Param",
            "c.Query",
            "c.DefaultQuery",
            "c.PostForm",
            "c.DefaultPostForm",
            "c.GetHeader",
            "c.GetRawData",
            "c.ShouldBindJSON",
            "c.ShouldBind",
            // Echo
            "c.Param",
            "c.QueryParam",
            "c.FormValue",
            "c.Request().Body",
            // Fiber
            "c.Params",
            "c.Query",
            "c.Body",
            "c.FormValue",
            "c.Get",
        ]
    }

    fn propagator_rules(&self) -> &'static [PropagatorRule] {
        GO_PROPAGATORS
    }

    fn classify_sanitizer(&self, call: &str) -> Option<SanitizerKind> {
        go_classify_sanitizer(call)
    }

    fn route_context_hints(&self) -> &'static [&'static str] {
        &[
            "http.HandleFunc",
            "http.Handle",
            "r.GET(",
            "r.POST(",
            "r.PUT(",
            "r.DELETE(", // Gin
            "e.GET(",
            "e.POST(", // Echo
            "app.Get(",
            "app.Post(", // Fiber
            "http.ResponseWriter",
            "*http.Request",
            "c.JSON(",
            "c.String(",
            "c.Status(", // Gin response
            "c.JSON(",
            "c.String(", // Echo/Fiber response
        ]
    }

    fn test_context_hints(&self) -> &'static [&'static str] {
        &[
            "func Test",
            "testing.T",
            "t.Error(",
            "t.Fatal(",
            "t.Run(",
            "testify",
        ]
    }

    fn response_method_names(&self) -> &'static [&'static str] {
        &["WriteHeader", "SetCookie", "WriteString", "ServeHTTP"]
    }

    fn db_api_method_names(&self) -> &'static [&'static str] {
        &["QueryRow", "Exec", "Begin", "First", "Updates"]
    }

    fn shell_api_method_names(&self) -> &'static [&'static str] {
        &["Command", "Output", "CombinedOutput", "Start"]
    }
}
