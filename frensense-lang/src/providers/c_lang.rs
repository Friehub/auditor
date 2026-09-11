// SPDX-License-Identifier: MIT
//! C [`LanguageSpec`] implementation.
//!
//! Covers C99/C11 tree-sitter grammar node kinds.

use tree_sitter::Node;

use crate::spec::{
    call_last_segment, node_text, Import, LanguageSpec, NodeRole, PackageCategory, PropagatorRule,
    SanitizerKind, TaintOrigin,
};

// ── AST classification ────────────────────────────────────────────────────────

fn classify_c(kind: &str) -> NodeRole {
    match kind {
        // ── Functions ────────────────────────────────────────────────────
        "function_definition" => NodeRole::Function {
            is_method: false,
            name_field: Some("declarator"),
            params_field: "declarator", // walked from the declarator
            body_field: "body",
        },

        // ── Declarations / assignments ───────────────────────────────────
        "declaration" | "init_declarator" => NodeRole::Declaration {
            name_field: "declarator",
            value_field: "value",
        },
        "assignment_expression" => NodeRole::Assignment {
            lhs_field: "left",
            rhs_field: "right",
        },

        // ── Calls ────────────────────────────────────────────────────────
        "call_expression" => NodeRole::Call {
            callee_field: "function",
            args_field: "arguments",
        },
        "field_expression" => NodeRole::MemberAccess {
            object_field: "argument",
            property_field: "field",
        },
        "subscript_expression" => NodeRole::MemberAccess {
            object_field: "argument",
            property_field: "index",
        },

        // ── Control flow ─────────────────────────────────────────────────
        "if_statement" | "conditional_expression" | "switch_statement" => NodeRole::Branch,
        "for_statement" | "while_statement" | "do_statement" => NodeRole::Loop,
        "return_statement" => NodeRole::Return,

        // ── Structural ───────────────────────────────────────────────────
        "compound_statement" => NodeRole::Block,
        "identifier" => NodeRole::Identifier,
        "string_literal" | "char_literal" | "number_literal" | "true" | "false" | "null" => {
            NodeRole::Literal
        }

        _ => NodeRole::Other,
    }
}

// ── Import extraction (C #include) ────────────────────────────────────────────

fn extract_c_includes(root: Node<'_>, source: &str) -> Vec<Import> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();
        if node.kind() == "preproc_include" {
            let pkg = node
                .named_child(0)
                .map(|n| {
                    let raw = node_text(n, source);
                    // Strip <stdio.h> or "myheader.h"
                    raw.trim_matches(['<', '>', '"', '\'']).to_owned()
                })
                .unwrap_or_default();
            if !pkg.is_empty() {
                let local = pkg
                    .rsplit('/')
                    .next()
                    .unwrap_or(&pkg)
                    .trim_end_matches(".h")
                    .to_owned();
                imports.push(Import {
                    local_name: local,
                    package: pkg,
                    symbol: None,
                });
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

// ── Package knowledge ─────────────────────────────────────────────────────────

fn c_package_category(pkg: &str) -> Option<PackageCategory> {
    let base = pkg.trim_end_matches(".h");
    match base {
        "sqlite3" | "mysql" | "libpq" | "pgsql" => Some(PackageCategory::SqlDatabase),
        "curl" | "libcurl" => Some(PackageCategory::HttpClient),
        "openssl/md5" | "openssl/sha" => Some(PackageCategory::Crypto),
        _ => None,
    }
}

// ── Static sink/source tables ─────────────────────────────────────────────────

static C_SINK_NAMES: &[(&str, &str)] = &[
    // Code Execution
    ("eval", "CodeExecution"),
    ("system", "CommandInjection"),
    ("popen", "CommandInjection"),
    ("exec", "CommandInjection"),
    ("execve", "CommandInjection"),
    ("execl", "CommandInjection"),
    ("execlp", "CommandInjection"),
    ("execvp", "CommandInjection"),
    ("execvpe", "CommandInjection"),
    ("spawn", "CommandInjection"),
    ("spawnSync", "CommandInjection"),
    // SQL Injection
    ("mysql_query", "SqlInjection"),
    ("sqlite3_exec", "SqlInjection"),
    ("execute", "SqlInjection"),
    ("query", "SqlInjection"),
    ("prepare", "SqlInjection"),
    // Path Traversal
    ("fopen", "PathTraversal"),
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
    // Buffer Overflow / Memory Safety
    ("gets", "BufferOverflow"),
    ("strcpy", "BufferOverflow"),
    ("strcat", "BufferOverflow"),
    ("sprintf", "FormatString"),
    ("vsprintf", "FormatString"),
    ("printf", "FormatString"),
    ("snprintf", "FormatString"),
    ("sscanf", "FormatString"),
    ("memcpy", "BufferOverflow"),
    ("memmove", "BufferOverflow"),
    ("memset", "BufferOverflow"),
    ("strncpy", "BufferOverflow"),
    ("strncat", "BufferOverflow"),
    ("mktemp", "PathTraversal"),
    ("tmpnam", "PathTraversal"),
    // SSRF
    ("fetch", "Ssrf"),
    ("get", "Ssrf"),
    ("post", "Ssrf"),
    ("request", "Ssrf"),
    ("got", "Ssrf"),
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
    ("ejs.render", "TemplateSsti"),
    ("pug.compile", "TemplateSsti"),
    ("handlebars.compile", "TemplateSsti"),
    ("nunjucks.render", "TemplateSsti"),
    // Unsafe Deserialization
    ("pickle.loads", "UnsafeDeserialize"),
    ("yaml.load", "UnsafeDeserialize"),
    ("bincode::deserialize", "UnsafeDeserialize"),
    ("serde_json::from_str", "UnsafeDeserialize"),
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
];

static C_SOURCE_PATTERNS: &[&str] = &["argv", "getenv", "fgets", "scanf", "stdin"];

static C_PROPAGATORS: &[PropagatorRule] = &[
    PropagatorRule {
        call: "sprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "snprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "strcat",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "strcpy",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "strdup",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
];

// ── CSpec ─────────────────────────────────────────────────────────────────────

pub struct CSpec;

impl LanguageSpec for CSpec {
    fn name(&self) -> &'static str {
        "c"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["c", "h"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "c-grammar")]
        return tree_sitter_c::LANGUAGE.into();
        #[cfg(not(feature = "c-grammar"))]
        panic!("frensense-lang: 'c-grammar' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_c(kind)
    }

    fn wrap_region(&self, code: &str) -> String {
        format!("void _region() {{\n{}\n}}", code)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["preproc_include"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_c_includes(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(
            r"
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @name))
            (declaration
                declarator: (function_declarator
                    declarator: (identifier) @name))
        ",
        )
    }

    fn call_query(&self) -> Option<&'static str> {
        Some(
            r"
            (function_definition
                declarator: (function_declarator declarator: (identifier) @caller)
                body: (_
                    (expression_statement
                        (call_expression function: (identifier) @call))))
        ",
        )
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        c_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        _type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        match name? {
            "argc" | "argv" => Some(TaintOrigin::UserInput),
            _ => None,
        }
    }

    fn known_sink_names(&self) -> &'static [(&'static str, &'static str)] {
        C_SINK_NAMES
    }

    fn known_source_patterns(&self) -> &'static [&'static str] {
        C_SOURCE_PATTERNS
    }

    fn propagator_rules(&self) -> &'static [PropagatorRule] {
        C_PROPAGATORS
    }

    fn classify_sanitizer(&self, call: &str) -> Option<SanitizerKind> {
        match call_last_segment(call) {
            "atoi" | "atol" | "atof" | "strtol" | "strtoul" => Some(SanitizerKind::Full),
            _ => None,
        }
    }

    fn test_context_hints(&self) -> &'static [&'static str] {
        &["CU_ASSERT", "assert(", "TEST(", "EXPECT_", "mu_assert"]
    }

    fn response_method_names(&self) -> &'static [&'static str] {
        &[]
    }

    fn db_api_method_names(&self) -> &'static [&'static str] {
        &[]
    }

    fn shell_api_method_names(&self) -> &'static [&'static str] {
        &[]
    }

    fn route_registration_patterns(&self) -> &'static [&'static str] {
        &[]
    }
}
