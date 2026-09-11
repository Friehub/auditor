// SPDX-License-Identifier: MIT
//! Rust [`LanguageSpec`] implementation.

use tree_sitter::Node;

use crate::spec::{
    call_last_segment, Import, LanguageSpec, NodeRole, PackageCategory, PropagatorRule,
    SanitizerKind, TaintOrigin,
};

// ── AST classification ────────────────────────────────────────────────────────

fn classify_rust(kind: &str) -> NodeRole {
    match kind {
        // ── Functions ────────────────────────────────────────────────────
        // All function kinds in Rust use `function_item` regardless of whether
        // they appear at top level or inside an `impl` block.
        "function_item" => NodeRole::Function {
            is_method: false, // impl context determined by parent
            name_field: Some("name"),
            params_field: "parameters",
            body_field: "body",
        },
        "closure_expression" => NodeRole::Function {
            is_method: false,
            name_field: None,
            params_field: "parameters",
            body_field: "body",
        },

        // ── Declarations / assignments ───────────────────────────────────
        "let_declaration" => NodeRole::Declaration {
            name_field: "pattern",
            value_field: "value",
        },
        "assignment_expression" => NodeRole::Assignment {
            lhs_field: "left",
            rhs_field: "right",
        },
        "compound_assignment_expr" => NodeRole::Assignment {
            lhs_field: "left",
            rhs_field: "right",
        },

        // ── Calls ────────────────────────────────────────────────────────
        "call_expression" => NodeRole::Call {
            callee_field: "function",
            args_field: "arguments",
        },
        "method_call_expression" => NodeRole::Call {
            callee_field: "method",
            args_field: "arguments",
        },
        "macro_invocation" => NodeRole::Call {
            callee_field: "macro",
            args_field: "token_tree",
        },
        "field_expression" => NodeRole::MemberAccess {
            object_field: "value",
            property_field: "field",
        },

        // ── Control flow ─────────────────────────────────────────────────
        "if_expression" | "if_let_expression" | "match_expression" => NodeRole::Branch,
        "for_expression" | "while_expression" | "while_let_expression" | "loop_expression" => {
            NodeRole::Loop
        }
        "return_expression" => NodeRole::Return,
        "try_expression" => NodeRole::ErrorPropagation, // the `?` operator
        "await_expression" => NodeRole::Await,

        // ── Structural ───────────────────────────────────────────────────
        "block" => NodeRole::Block,
        "use_declaration" => NodeRole::Import,
        "identifier" | "scoped_identifier" | "type_identifier" | "field_identifier"
        | "primitive_type" => NodeRole::Identifier,
        "string_literal" | "raw_string_literal" | "integer_literal" | "float_literal"
        | "boolean_literal" => NodeRole::Literal,

        _ => NodeRole::Other,
    }
}

// ── Import extraction ─────────────────────────────────────────────────────────

fn extract_rust_imports(root: Node<'_>, source: &str) -> Vec<Import> {
    use crate::spec::node_text;

    let mut imports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();

        if node.kind() == "use_declaration" {
            // `use axum::Router;`
            // `use axum::{Router, extract::Json};`
            // `use sqlx::PgPool as Pool;`
            let text = node_text(node, source)
                .trim_start_matches("use ")
                .trim_end_matches(';')
                .trim();
            flatten_rust_use(text, &mut imports);
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

/// Recursively expand `axum::{Router, extract::Json}` into flat imports.
fn flatten_rust_use(path: &str, out: &mut Vec<Import>) {
    let path = path.trim();
    if let Some(brace_start) = path.find('{') {
        let prefix = &path[..brace_start];
        let inner = path[brace_start + 1..].trim_end_matches('}');
        for segment in split_rust_use_list(inner) {
            let full = format!("{}{}", prefix, segment.trim());
            flatten_rust_use(&full, out);
        }
    } else if let Some((pkg, local)) = path.rsplit_once(" as ") {
        let pkg_base = pkg.split("::").next().unwrap_or(pkg);
        out.push(Import {
            local_name: local.trim().to_owned(),
            package: pkg_base.to_owned(),
            symbol: Some(pkg.trim().to_owned()),
        });
    } else {
        let pkg_base = path.split("::").next().unwrap_or(path);
        let local = path.rsplit("::").next().unwrap_or(path);
        out.push(Import {
            local_name: local.to_owned(),
            package: pkg_base.to_owned(),
            symbol: Some(path.to_owned()),
        });
    }
}

fn split_rust_use_list(inner: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in inner.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            ',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    parts
}

// ── Package catalogue ─────────────────────────────────────────────────────────

fn rust_package_category(pkg: &str) -> Option<PackageCategory> {
    match pkg {
        "axum" | "actix-web" | "actix_web" | "rocket" | "warp" | "tide" | "poem" | "salvo"
        | "ntex" | "viz" | "gotham" => Some(PackageCategory::HttpFramework),

        "sqlx" | "diesel" | "sea-orm" | "sea_orm" | "tokio-postgres" | "rusqlite" | "mysql"
        | "mysql_async" | "tiberius" | "quaint" => Some(PackageCategory::SqlDatabase),

        "mongodb" | "redis" | "elasticsearch" | "cassandra-cpp" => {
            Some(PackageCategory::NoSqlDatabase)
        }

        "tokio" => None, // runtime — tokio::process is a sink but tokio itself is not
        "std" => None,   // std::process::Command handled via known_sink_names

        "reqwest" | "hyper" | "ureq" | "surf" | "isahc" | "attohttpc" => {
            Some(PackageCategory::HttpClient)
        }

        "tera" | "handlebars" | "askama" | "minijinja" | "liquid" => {
            Some(PackageCategory::TemplateEngine)
        }

        "serde_pickle" | "bincode" | "rmp-serde" | "ciborium" | "postcard" => {
            Some(PackageCategory::Deserialization)
        }

        "ring" | "rustls" | "openssl" | "aes" | "sha2" | "hmac" | "rand" => {
            Some(PackageCategory::Crypto)
        }

        "tokio-test" | "mockall" | "proptest" | "rstest" => Some(PackageCategory::Testing),

        _ => None,
    }
}

// ── Param taint ───────────────────────────────────────────────────────────────

fn rust_classify_param(_name: Option<&str>, ann: Option<&str>) -> Option<TaintOrigin> {
    let a = ann?.split('<').next().unwrap_or(ann?).trim();
    // Strip leading reference / mut
    let a = a.trim_start_matches('&').trim_start_matches("mut").trim();
    match a {
        // Axum extractors
        "Json" | "Form" | "Query" | "Path" | "Bytes" | "Multipart" | "TypedHeader"
        | "Extension" | "RawBody" | "RawQuery" | "RawPath" => Some(TaintOrigin::UserInput),
        // Actix-web extractors
        "web::Json" | "web::Form" | "web::Query" | "web::Path" | "web::Bytes" | "web::Payload"
        | "HttpRequest" => Some(TaintOrigin::UserInput),
        // Rocket
        "&RocketRequest" | "Form" | "Json" | "Data" => Some(TaintOrigin::UserInput),
        _ => None,
    }
}

// ── Sanitizers ────────────────────────────────────────────────────────────────

fn rust_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        // Numeric parse: `"42".parse::<u64>()` — kills injection
        "parse" => Some(SanitizerKind::Full),
        // HTML
        "clean" | "ammonia" | "escape_html" => Some(SanitizerKind::HtmlEscape),
        // URL
        "encode" | "percent_encode" | "utf8_percent_encode" => Some(SanitizerKind::UrlEncode),
        // Path
        "canonicalize" | "normalize" => Some(SanitizerKind::PathNormalize),
        _ => None,
    }
}

// ── Propagators ───────────────────────────────────────────────────────────────

static RUST_PROPAGATORS: &[PropagatorRule] = &[
    // format! — any arg taints the return
    PropagatorRule {
        call: "format",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "format_args",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "write",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "writeln",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "println",
        tainted_arg: None,
        tainted_receiver: false,
    },
    // String conversions — receiver taints return
    PropagatorRule {
        call: "to_string",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "to_owned",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "clone",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "into",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "as_str",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "as_bytes",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "as_ref",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "from_utf8",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "from",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // String methods
    PropagatorRule {
        call: "replace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "to_lowercase",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "to_uppercase",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trim",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trim_start",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trim_end",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "split",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "concat",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "push_str",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "push",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    // Iterator adaptors
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
        call: "collect",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "flat_map",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // unwrap / expect: propagates taint from Result<T,_> / Option<T>
    PropagatorRule {
        call: "unwrap",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "expect",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "unwrap_or",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "ok",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "ok_or",
        tainted_arg: None,
        tainted_receiver: true,
    },
];

const RUST_SYMBOL_QUERY: &str = r#"
    (function_item name: (identifier) @name)
    (struct_item   name: (type_identifier) @name)
    (enum_item     name: (type_identifier) @name)
    (trait_item    name: (type_identifier) @name)
    (impl_item     type: (type_identifier) @name)
"#;

const RUST_CALL_QUERY: &str = r#"
    (function_item name: (identifier) @caller
        body: (block
            (expression_statement
                (call_expression function: (identifier) @call))))
    (function_item name: (identifier) @caller
        body: (block
            (expression_statement
                (method_call_expression method: (field_identifier) @call))))
    (function_item name: (identifier) @caller
        body: (block
            (expression_statement
                (macro_invocation macro: (identifier) @call))))
"#;

// ── RustSpec ──────────────────────────────────────────────────────────────────

pub struct RustSpec;

impl LanguageSpec for RustSpec {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["rs"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "rust-grammar")]
        return tree_sitter_rust::LANGUAGE.into();
        #[cfg(not(feature = "rust-grammar"))]
        panic!("frensense-lang: 'rust-grammar' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_rust(kind)
    }

    fn wrap_region(&self, code: &str) -> String {
        format!("fn _region() {{\n{}\n}}", code)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["use_declaration"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_rust_imports(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(RUST_SYMBOL_QUERY)
    }
    fn call_query(&self) -> Option<&'static str> {
        Some(RUST_CALL_QUERY)
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        rust_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        rust_classify_param(name, type_annotation)
    }

    fn is_http_route_decorator(&self, name: &str) -> bool {
        // Rocket proc-macro attributes: `#[get("/")]`, `#[post("/")]`, etc.
        matches!(
            name,
            "get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "route"
        )
    }

    fn request_param_names(&self) -> &'static [&'static str] {
        // Axum/Actix: parameter names matter less than types; type-based
        // detection via classify_param_taint is the primary mechanism.
        &["req", "request"]
    }

    fn known_sink_names(&self) -> &'static [(&'static str, &'static str)] {
        &[
            // SQL Injection
            ("execute", "SqlInjection"),
            ("fetch", "SqlInjection"),
            ("fetch_one", "SqlInjection"),
            ("fetch_all", "SqlInjection"),
            ("query", "SqlInjection"),
            ("query_as", "SqlInjection"),
            ("raw_sql", "SqlInjection"),
            ("executeRaw", "SqlInjection"),
            ("queryRaw", "SqlInjection"),
            ("prepare", "SqlInjection"),
            // Command Injection
            ("Command", "CommandInjection"),
            ("arg", "CommandInjection"),
            ("args", "CommandInjection"),
            ("status", "CommandInjection"),
            ("output", "CommandInjection"),
            ("spawn", "CommandInjection"),
            ("spawnSync", "CommandInjection"),
            ("exec", "CommandInjection"),
            // Path Traversal
            ("read", "PathTraversal"),
            ("read_to_string", "PathTraversal"),
            ("open", "PathTraversal"),
            ("create", "PathTraversal"),
            ("write", "PathTraversal"),
            ("readFile", "PathTraversal"),
            ("writeFile", "PathTraversal"),
            ("readFileSync", "PathTraversal"),
            ("join", "PathTraversal"),
            ("unlink", "PathTraversal"),
            ("stat", "PathTraversal"),
            ("access", "PathTraversal"),
            // SSRF
            ("reqwest::get", "Ssrf"),
            ("Client::get", "Ssrf"),
            ("ureq::get", "Ssrf"),
            ("http.get", "Ssrf"),
            ("https.get", "Ssrf"),
            ("got", "Ssrf"),
            ("get", "Ssrf"),
            ("post", "Ssrf"),
            ("send", "Ssrf"),
            ("request", "Ssrf"),
            ("fetch", "Ssrf"),
            // Open Redirect
            ("redirect", "OpenRedirect"),
            // XSS
            ("innerHTML", "XssDom"),
            ("outerHTML", "XssDom"),
            ("document.write", "XssDom"),
            ("dangerouslySetInnerHTML", "XssDom"),
            // SSTI
            ("render", "TemplateSsti"),
            ("render_template", "TemplateSsti"),
            ("render_template_string", "TemplateSsti"),
            // Unsafe Memory
            ("transmute", "UnsafeMemory"),
            ("transmute_copy", "UnsafeMemory"),
            ("from_utf8_unchecked", "UnsafeMemory"),
            ("from_raw_parts", "UnsafeMemory"),
            // Unsafe Deserialization
            ("bincode::deserialize", "UnsafeDeserialize"),
            ("serde_json::from_str", "UnsafeDeserialize"),
            ("serde_json::from_value", "UnsafeDeserialize"),
            ("serde_pickle::from_slice", "UnsafeDeserialize"),
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
        ]
    }

    fn known_source_patterns(&self) -> &'static [&'static str] {
        &[
            // Axum
            "Json",
            "Path",
            "Query",
            "Form",
            "Bytes",
            "Multipart",
            // Actix
            "web::Json",
            "web::Path",
            "web::Query",
            "web::Form",
            // Environment
            "std::env::var",
            "env::var",
            "var",
        ]
    }

    fn propagator_rules(&self) -> &'static [PropagatorRule] {
        RUST_PROPAGATORS
    }

    fn classify_sanitizer(&self, call: &str) -> Option<SanitizerKind> {
        rust_classify_sanitizer(call)
    }

    fn route_context_hints(&self) -> &'static [&'static str] {
        &[
            "#[get(",
            "#[post(",
            "#[put(",
            "#[delete(",
            "#[patch(", // Rocket
            ".route(",
            ".get(",
            ".post(", // Axum/Warp
            "IntoResponse",
            "impl Responder",
            "HttpResponse",
            "Json(",
            "StatusCode::",
            "web::scope",
            "web::resource", // Actix
        ]
    }

    fn test_context_hints(&self) -> &'static [&'static str] {
        &[
            "#[test]",
            "#[tokio::test]",
            "#[async_std::test]",
            "assert_eq!",
            "assert!",
            "proptest!",
        ]
    }

    fn response_method_names(&self) -> &'static [&'static str] {
        &[
            "ok",
            "created",
            "internal_server_error",
            "into_response",
            "content_type",
            "body",
            "finish",
        ]
    }

    fn db_api_method_names(&self) -> &'static [&'static str] {
        &[
            "fetch_one",
            "fetch_optional",
            "fetch_all",
            "load",
            "get_result",
            "insert_into",
        ]
    }

    fn shell_api_method_names(&self) -> &'static [&'static str] {
        &["Command::new", "status"]
    }
}
