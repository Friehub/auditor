// SPDX-License-Identifier: MIT

//! Corpus-driven source/sink registry.
//!
//! Extracts source types and sink function names from positive corpus files
//! at load time. Replaces hardcoded framework type arrays and sink lists.

use crate::data_flow::TaintOrigin;
use frensense_lang::spec_for_ext;
use rustc_hash::FxHashMap;
use std::path::Path;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkTier {
    HighConfidence, // min_occurrences: 1 — known dangerous, no FP risk
    Standard,       // min_occurrences: 2 — current default
    Suspicious,     // min_occurrences: 3 — novel patterns, need more evidence
}

impl SinkTier {
    pub fn min_occurrences(&self) -> usize {
        match self {
            Self::HighConfidence => 1,
            Self::Standard => 2,
            Self::Suspicious => 3,
        }
    }
}

// Hardcoded high-confidence sinks that are ALWAYS registered regardless of occurrence:
pub const ALWAYS_REGISTER_SINKS: &[&str] = &[
    // Code Execution
    "eval",
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "Function",
    "setTimeout",
    "setInterval",
    "runInNewContext",
    "runInThisContext",
    "require",
    "import",
    "Command::new",
    "args",
    // SQL Injection
    "query",
    "execute",
    "executeRaw",
    "queryRaw",
    "raw",
    "sql_query",
    "prepare",
    // Command Injection
    "execFile",
    "execFileSync",
    "shelljs.exec",
    "execa",
    // Path Traversal
    "readFile",
    "writeFile",
    "readFileSync",
    "join",
    "unlink",
    "stat",
    "access",
    "read_to_string",
    "read",
    "write",
    "open",
    // SSRF
    "fetch",
    "axios.get",
    "axios.post",
    "http.get",
    "https.get",
    "got",
    "request",
    "node-fetch",
    "reqwest::get",
    "Client::get",
    "Uri::from",
    "ureq::get",
    // Open Redirect
    "redirect",
    "location.href",
    "window.location",
    // XSS
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "dangerouslySetInnerHTML",
    // MongoDB / ORM calls
    "update",
    "updateOne",
    "updateMany",
    "insert",
    "insertOne",
    "insertMany",
    "delete",
    "deleteOne",
    "deleteMany",
    "find",
    "findOne",
    "findAll",
    "query",
    // MongoDB / ORM calls
    "update",
    "updateOne",
    "updateMany",
    "insert",
    "insertOne",
    "insertMany",
    "delete",
    "deleteOne",
    "deleteMany",
    "find",
    "findOne",
    "findAll",
    "query",
    // Storage Write
    "put",
    "setItem",
    // Log Leak
    "log",
    "error",
    "info",
    "debug",
    // Unsafe Memory (Rust)
    "transmute",
    "transmute_copy",
    "from_utf8_unchecked",
    "from_raw_parts",
    // MongoDB / NoSQL operator sinks (used as object property keys)
    "$where",
    "$regex",
    "$gt",
    "$lt",
    "$ne",
    "$in",
    "$nin",
    "$exists",
    "$expr",
    "$function",
    "$accumulator",
    // Framework Specific (Cloudflare, Express, Next.js, Hono, Prisma)
    "c.redirect",
    "env.KV.put",
    "KVNamespace.put",
    "KVNamespace.delete",
    "env.DB.prepare",
    "res.send",
    "res.json",
    "res.redirect",
    "res.render",
    "revalidatePath",
    "prisma.queryRawUnsafe",
    "prisma.executeRawUnsafe",
    "R2Bucket.put",
    "D1Database.prepare",
    "DurableObjectStub.fetch",
    "Queue.send",
    // SSTI — Template engine renders
    "ejs.render",
    "ejs.renderFile",
    "pug.compile",
    "pug.render",
    "handlebars.compile",
    "handlebars.render",
    "nunjucks.render",
    "nunjucks.renderString",
    "nunjucks.renderFile",
    "marko.render",
    "eta.render",
    "swig.render",
    "liquid.render",
    "mustache.render",
    "jade.render",
    "react-dom/server.renderToString",
    "vue-server-renderer.renderToString",
    "render_template",
    "render_template_string",
    // Insecure Deserialization
    "yaml.load",
    "js-yaml.load",
    "pickle.loads",
    "bincode::deserialize",
    "msgpack.decode",
    "msgpack.unpack",
    "php.unserialize",
    "ObjectInputStream.readObject",
    "BinaryFormatter.Deserialize",
    // Prototype Pollution
    "Object.assign",
    "_.merge",
    "lodash.merge",
    "_.defaultsDeep",
    "_.set",
    "$.extend",
    "jQuery.extend",
    "angular.merge",
    "setPrototypeOf",
    // XXE — XML parsers
    "DOMParser",
    "libxml2",
    "SAXParser",
    "XMLReader",
    "DocumentBuilder",
    "DocumentBuilderFactory",
    "XmlDocument",
    "XDocument",
    "XmlTextReader",
    "simplexml_load_string",
    "DOMDocument",
    // JWT
    "jwt.verify",
    "jwt.decode",
    "jwt.sign",
    "jsonwebtoken.verify",
    "jsonwebtoken.decode",
    "jsonwebtoken.sign",
    "JWT.verify",
    "JWT.decode",
];

/// Reduced sink list for compiler-aware mode.
/// When `use_compiler=true`, OXC module resolution covers generic sinks
/// like `query`, `readFile`, `fetch` by resolving imports to their source modules.
/// This list keeps only:
/// - Truly dangerous bare calls (eval, exec, transmute)
/// - Framework-specific sinks that can't be resolved through imports
/// - MongoDB operators (property keys, not function calls)
pub const ALWAYS_REGISTER_SINKS_COMPILER_AWARE: &[&str] = &[
    // Code Execution — truly dangerous bare calls
    "eval",
    "exec",
    "execSync",
    "Function",
    "setTimeout",
    "setInterval",
    "runInNewContext",
    "runInThisContext",
    // Command Injection
    "execFile",
    "execFileSync",
    "execa",
    // Unsafe Memory (Rust)
    "transmute",
    "transmute_copy",
    "from_utf8_unchecked",
    "from_raw_parts",
    // MongoDB / NoSQL operator sinks (property keys, not function calls)
    "$where",
    "$regex",
    "$gt",
    "$lt",
    "$ne",
    "$in",
    "$nin",
    "$exists",
    "$expr",
    "$function",
    "$accumulator",
    // Framework Specific — can't be resolved through imports
    "c.redirect",
    "env.KV.put",
    "KVNamespace.put",
    "KVNamespace.delete",
    "env.DB.prepare",
    "res.send",
    "res.json",
    "res.redirect",
    "res.render",
    "revalidatePath",
    "prisma.queryRawUnsafe",
    "prisma.executeRawUnsafe",
    "R2Bucket.put",
    "D1Database.prepare",
    "DurableObjectStub.fetch",
    "Queue.send",
    // SSTI — template engine renders (module-qualified, keep as fallback)
    "ejs.render",
    "ejs.renderFile",
    "pug.compile",
    "pug.render",
    "handlebars.compile",
    "handlebars.render",
    "nunjucks.render",
    "nunjucks.renderString",
    "nunjucks.renderFile",
    "marko.render",
    "eta.render",
    "swig.render",
    "liquid.render",
    "mustache.render",
    "jade.render",
    "react-dom/server.renderToString",
    "vue-server-renderer.renderToString",
    "render_template",
    "render_template_string",
    // Insecure Deserialization
    "yaml.load",
    "js-yaml.load",
    "pickle.loads",
    "bincode::deserialize",
    "msgpack.decode",
    "msgpack.unpack",
    "php.unserialize",
    "ObjectInputStream.readObject",
    "BinaryFormatter.Deserialize",
    // Prototype Pollution
    "Object.assign",
    "_.merge",
    "lodash.merge",
    "_.defaultsDeep",
    "_.set",
    "$.extend",
    "jQuery.extend",
    "angular.merge",
    "setPrototypeOf",
    // XXE — XML parsers
    "DOMParser",
    "libxml2",
    "SAXParser",
    "XMLReader",
    "DocumentBuilder",
    "DocumentBuilderFactory",
    "XmlDocument",
    "XDocument",
    "XmlTextReader",
    "simplexml_load_string",
    "DOMDocument",
    // JWT
    "jwt.verify",
    "jwt.decode",
    "jwt.sign",
    "jsonwebtoken.verify",
    "jsonwebtoken.decode",
    "jsonwebtoken.sign",
    "JWT.verify",
    "JWT.decode",
];

/// Return `ALWAYS_REGISTER_SINKS` as `(name, SinkCategory)` pairs.
/// Used by `ImportMapProvider::known_sink_names()`.
pub fn always_register_sinks_with_categories() -> Vec<(&'static str, SinkCategory)> {
    ALWAYS_REGISTER_SINKS
        .iter()
        .map(|&name| (name, SinkCategory::from_sink_name(name)))
        .collect()
}

/// Return compiler-aware sink list as `(name, SinkCategory)` pairs.
pub fn always_register_sinks_compiler_aware() -> Vec<(&'static str, SinkCategory)> {
    ALWAYS_REGISTER_SINKS_COMPILER_AWARE
        .iter()
        .map(|&name| (name, SinkCategory::from_sink_name(name)))
        .collect()
}

/// Return the hardcoded source patterns.
/// Used by `ImportMapProvider::known_source_patterns()`.
pub fn always_register_source_patterns() -> Vec<&'static str> {
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

pub fn get_sink_tier(sink: &str) -> SinkTier {
    let base = sink.rsplit('.').next().unwrap_or(sink);
    if ALWAYS_REGISTER_SINKS.contains(&base) {
        SinkTier::HighConfidence
    } else {
        SinkTier::Standard
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkCategory {
    CodeExecution,
    SqlInjection,
    NoSqlInjection,
    CommandInjection,
    PathTraversal,
    Ssrf,
    OpenRedirect,
    Xss,
    StorageWrite,
    LogLeak,
    ResponseLeak,
    CredentialLeak,
    Unknown,
}

impl SinkCategory {
    /// Returns the Common Weakness Enumeration (CWE) ID for this sink category.
    pub fn cwe(&self) -> u32 {
        match self {
            Self::CodeExecution => 94,    // Improper Control of Generation of Code
            Self::SqlInjection => 89,     // SQL Injection
            Self::NoSqlInjection => 943, // Improper Neutralization of Special Elements in Data Query Logic
            Self::CommandInjection => 78, // OS Command Injection
            Self::PathTraversal => 22,   // Path Traversal
            Self::Ssrf => 918,           // Server-Side Request Forgery
            Self::OpenRedirect => 601,   // URL Redirection to Untrusted Site
            Self::Xss => 79,             // Cross-site Scripting
            Self::StorageWrite => 200, // Exposure of Sensitive Information to an Unauthorized Actor
            Self::LogLeak => 532,      // Insertion of Sensitive Information into Log File
            Self::ResponseLeak => 200, // Exposure of Sensitive Information
            Self::CredentialLeak => 798, // Use of Hard-coded Credentials
            Self::Unknown => 0,        // Unknown/Uncategorized
        }
    }

    pub fn from_sink_name(sink: &str) -> Self {
        let s = sink.to_lowercase();
        if s.contains("eval") || s.contains("exec") && !s.contains("execsync") {
            Self::CodeExecution
        } else if s.contains("query") || s.contains("execute") {
            Self::SqlInjection
        } else if s.contains("spawn") || s.contains("system") || s.contains("execsync") {
            Self::CommandInjection
        } else if s.contains("readfile") || s.contains("writefile") || s.contains("join") {
            Self::PathTraversal
        } else if s.contains("fetch") || s.contains("axios") || s.contains("http.get") {
            Self::Ssrf
        } else if s.contains("redirect") {
            Self::OpenRedirect
        } else if s.contains("innerhtml") || s.contains("document.write") {
            Self::Xss
        } else if s.contains("put") || s.contains("set") {
            Self::StorageWrite
        } else if s.contains("log") || s.contains("logger") {
            Self::LogLeak
        } else if s.contains("send") || s.contains("json") {
            Self::ResponseLeak
        } else {
            Self::Unknown
        }
    }
}

/// Relevance multiplier: how likely a given TaintOrigin is to be a true positive
/// for a given SinkCategory. 1.0 = fully relevant, 0.0 = irrelevant.
/// This prevents false positives where e.g. FileSystem-origin data reaching an
/// SQL sink gets scored the same as UserInput-origin data.
#[must_use]
pub fn sink_taint_relevance(category: SinkCategory, origin: &TaintOrigin) -> f64 {
    match origin {
        TaintOrigin::UserInput => 1.0,
        TaintOrigin::Environment => match category {
            SinkCategory::CredentialLeak | SinkCategory::LogLeak => 0.9,
            _ => 0.5,
        },
        TaintOrigin::Database => match category {
            SinkCategory::SqlInjection | SinkCategory::NoSqlInjection => 0.7,
            SinkCategory::CodeExecution | SinkCategory::CommandInjection => 0.3,
            _ => 0.4,
        },
        TaintOrigin::Network => match category {
            SinkCategory::Ssrf | SinkCategory::OpenRedirect => 0.9,
            SinkCategory::CodeExecution | SinkCategory::CommandInjection => 0.6,
            _ => 0.5,
        },
        TaintOrigin::FileSystem => match category {
            SinkCategory::PathTraversal | SinkCategory::StorageWrite => 0.9,
            SinkCategory::LogLeak => 0.6,
            SinkCategory::SqlInjection | SinkCategory::CodeExecution => 0.2,
            _ => 0.3,
        },
        TaintOrigin::Custom(_) => 1.0,
    }
}

/// Infer the likely SinkCategory from a pattern ID string.
/// Pattern IDs follow `{lang}_{category}_{name}` convention — the name segment
/// often contains keywords like "sql", "cmd", "xss", etc.
#[must_use]
pub fn infer_sink_category(pattern_id: &str) -> Option<SinkCategory> {
    let lower = pattern_id.to_lowercase();
    if lower.contains("sql") || lower.contains("nosql") || lower.contains("sqli") {
        Some(SinkCategory::SqlInjection)
    } else if lower.contains("cmd") || lower.contains("command") || lower.contains("cmdi") {
        Some(SinkCategory::CommandInjection)
    } else if lower.contains("xss") || lower.contains("html_injection") {
        Some(SinkCategory::Xss)
    } else if lower.contains("ssrf") || lower.contains("server_side_request") {
        Some(SinkCategory::Ssrf)
    } else if lower.contains("path_traversal")
        || lower.contains("read_file")
        || lower.contains("write_file")
    {
        Some(SinkCategory::PathTraversal)
    } else if lower.contains("open_redirect") || lower.contains("redirect") {
        Some(SinkCategory::OpenRedirect)
    } else if lower.contains("eval") || lower.contains("code_exec") || lower.contains("rce") {
        Some(SinkCategory::CodeExecution)
    } else if lower.contains("credential")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("token")
    {
        Some(SinkCategory::CredentialLeak)
    } else if lower.contains("log") {
        Some(SinkCategory::LogLeak)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct CorpusSourceSinkRegistry {
    pub source_types: FxHashMap<String, usize>,
    /// Short method names learned from positive corpus (e.g. `"findOne"`, `"exec"`).
    pub sink_names: FxHashMap<String, (SinkCategory, usize)>,
    /// Qualified call expressions learned from positive corpus (e.g. `"collection.findOne"`).
    /// Used for suffix-match disambiguation to avoid matching generic method names on safe objects.
    pub qualified_sink_names: FxHashMap<String, (SinkCategory, usize)>,
    /// Call expressions that sanitize / escape tainted data, learned from negative corpus.
    pub sanitizer_names: FxHashMap<String, usize>,
    /// Known taint source patterns (member expressions like `req.body`, `process.env`).
    /// Initialized from hardcoded patterns and extended by provider's `known_source_patterns()`.
    pub source_patterns: Vec<String>,
}

impl Default for CorpusSourceSinkRegistry {
    fn default() -> Self {
        Self::from_sink_list(ALWAYS_REGISTER_SINKS)
    }
}

impl CorpusSourceSinkRegistry {
    /// Create a new registry with the given sink list.
    fn from_sink_list(sinks: &[&str]) -> Self {
        let mut sink_names = FxHashMap::default();
        let mut qualified_sink_names = FxHashMap::default();

        for &sink in sinks {
            let cat = SinkCategory::from_sink_name(sink);
            if sink.contains("::") || sink.contains('.') {
                qualified_sink_names.insert(sink.to_string(), (cat, 100));
            } else {
                sink_names.insert(sink.to_string(), (cat, 100));
            }
        }

        Self {
            source_types: FxHashMap::default(),
            sink_names,
            qualified_sink_names,
            sanitizer_names: FxHashMap::default(),
            source_patterns: always_register_source_patterns()
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }

    /// Create a new registry.
    /// When `use_compiler=true`, uses the reduced compiler-aware sink list.
    /// When `use_compiler=false`, uses the full hardcoded fallback list.
    pub fn new(use_compiler: bool) -> Self {
        if use_compiler {
            Self::from_sink_list(ALWAYS_REGISTER_SINKS_COMPILER_AWARE)
        } else {
            Self::default()
        }
    }

    /// Check if a type annotation string is a known source type.
    pub fn is_source_type(&self, type_str: &str) -> bool {
        let clean = type_str.trim();
        self.source_types.contains_key(clean)
    }

    /// Check if a text context contains a known taint source pattern.
    /// Used by `confidence.rs:is_real_source()` to verify that a definition
    /// is actually a taint source.
    pub fn is_source_pattern(&self, context: &str) -> bool {
        self.source_patterns.iter().any(|p| context.contains(p))
    }

    /// Check if a function name is a known sink (supports qualified names like "KV.put").
    pub fn is_sink(&self, qualified: &str) -> Option<SinkCategory> {
        if let Some((cat, _)) = self.qualified_sink_names.get(qualified) {
            return Some(*cat);
        }
        if let Some((cat, _)) = self.sink_names.get(qualified) {
            return Some(*cat);
        }
        let unqualified = qualified.rsplit('.').next().unwrap_or(qualified);
        if let Some((cat, count)) = self.sink_names.get(unqualified) {
            if *count >= 3 {
                return Some(*cat);
            }
        }
        None
    }

    /// Check if a full call expression string is a known sink.
    ///
    /// Checks in order:
    /// 1. Exact match on `sink_names` (bare function call like `exec`).
    /// 2. Exact match on `qualified_sink_names` (qualified like `collection.findOne`).
    /// 3. Suffix match: any entry in `sink_names` appears as the final `.`-delimited segment
    ///    of `expr`, guarded against safe built-in prefixes.
    pub fn is_sink_expr(&self, expr: &str) -> Option<SinkCategory> {
        // 1. Short-name exact match
        if let Some((cat, _)) = self.sink_names.get(expr) {
            return Some(*cat);
        }

        // 2. Qualified exact match
        if let Some((cat, _)) = self.qualified_sink_names.get(expr) {
            return Some(*cat);
        }

        // Safe built-in object prefixes — never a sink regardless of method name
        const SAFE_PREFIXES: &[&str] = &[
            "Object.", "Array.", "String.", "Number.", "Math.", "JSON.", "console.", "process.",
            "Promise.",
        ];
        for prefix in SAFE_PREFIXES {
            if expr.starts_with(prefix) {
                return None;
            }
        }

        // 3. Suffix match: last segment of a dotted call matches a known short sink
        if let Some(last_seg) = expr.rsplit('.').next() {
            // Strip any trailing call punctuation
            let clean = last_seg.trim_end_matches(['(', ')']);
            if let Some((cat, _)) = self.sink_names.get(clean) {
                return Some(*cat);
            }
        }

        None
    }

    /// Check if a call expression is a known sanitizer.
    ///
    /// Returns `true` when the call is known to clean tainted input so taint
    /// propagation should stop at the result variable.
    pub fn is_sanitizer_call(&self, expr: &str) -> bool {
        // Learned from negative corpus
        if self.sanitizer_names.contains_key(expr) {
            return true;
        }
        // Built-in heuristics — stable regardless of corpus content
        const SANITIZER_FRAGMENTS: &[&str] = &[
            "escape",
            "sanitize",
            "encode",
            "validate",
            "strip",
            "clean",
            "purify",
            "filter",
            "dompurify",
            "xss",
            "he.",
        ];
        let lower = expr.to_lowercase();
        for frag in SANITIZER_FRAGMENTS {
            if lower.contains(frag) {
                return true;
            }
        }
        false
    }

    /// Get source type count (for diagnostics).
    pub fn source_type_count(&self) -> usize {
        self.source_types.len()
    }

    /// Get sink name count (for diagnostics).
    pub fn sink_name_count(&self) -> usize {
        self.sink_names.len()
    }

    /// Merge another registry into this one (accumulates counts).
    pub fn merge(&mut self, other: &CorpusSourceSinkRegistry) {
        for (k, v) in &other.source_types {
            *self.source_types.entry(k.clone()).or_insert(0) += v;
        }
        for (k, (cat, count)) in &other.sink_names {
            let entry = self.sink_names.entry(k.clone()).or_insert((*cat, 0));
            entry.1 += count;
        }
        for (k, (cat, count)) in &other.qualified_sink_names {
            let entry = self
                .qualified_sink_names
                .entry(k.clone())
                .or_insert((*cat, 0));
            entry.1 += count;
        }
        for (k, v) in &other.sanitizer_names {
            *self.sanitizer_names.entry(k.clone()).or_insert(0) += v;
        }
        for pattern in &other.source_patterns {
            if !self.source_patterns.contains(pattern) {
                self.source_patterns.push(pattern.clone());
            }
        }
    }

    /// Prune entries below their specific threshold.
    pub fn prune(&mut self) {
        self.source_types.retain(|_, count| *count >= 2);

        self.sink_names
            .retain(|name, (_, count)| *count >= get_sink_tier(name).min_occurrences());

        self.qualified_sink_names
            .retain(|name, (_, count)| *count >= get_sink_tier(name).min_occurrences());

        self.sanitizer_names.retain(|_, count| *count >= 2);
    }
}

/// Build a registry from a set of positive source files.
///
/// Walks each file's AST to extract:
/// - Parameter type annotations → source types
/// - Call expression callee names → sink names
pub fn build_registry(positive_files: &[(String, String)]) -> CorpusSourceSinkRegistry {
    let mut registry = CorpusSourceSinkRegistry::default();

    for (source, ext) in positive_files {
        let (file_sources, file_sinks) = extract_sources_and_sinks(source, ext);

        // Count each type/sink once per file (not once per function)
        // to avoid over-counting multi-function positive files
        let mut seen_types = std::collections::HashSet::new();
        for ty in &file_sources {
            if seen_types.insert(ty.clone()) {
                *registry.source_types.entry(ty.clone()).or_insert(0) += 1;
            }
        }

        let mut seen_sinks = std::collections::HashSet::new();
        for sink in &file_sinks {
            let (short, qualified) = split_sink_name(sink);
            if seen_sinks.insert(short.clone()) {
                let cat = SinkCategory::from_sink_name(&short);
                let entry = registry.sink_names.entry(short).or_insert((cat, 0));
                entry.1 += 1;
            }
            if let Some(q) = qualified {
                let cat = SinkCategory::from_sink_name(&q);
                let entry = registry.qualified_sink_names.entry(q).or_insert((cat, 0));
                entry.1 += 1;
            }
        }

        // Parse explicit annotation overrides
        for line in source.lines() {
            if let Some(sink_name) = line.split("// frensense-sink:").nth(1) {
                let clean_name = sink_name.trim().to_string();
                let (short, qualified) = split_sink_name(&clean_name);

                let cat = SinkCategory::from_sink_name(&short);
                registry
                    .sink_names
                    .entry(short.clone())
                    .or_insert((cat, 0))
                    .1 += 100;

                if let Some(q) = qualified {
                    registry
                        .qualified_sink_names
                        .entry(q.clone())
                        .or_insert((cat, 0))
                        .1 += 100;
                }
            }
        }
    }

    registry.prune();
    registry
}

/// Extract parameter name and type from a function parameter node.
///
/// Returns `(param_name, type_string)`. The type string includes the full
/// type annotation text (e.g., `"Request"`, `"Json<User>"`, `"String"`).
pub fn extract_param_info(param: tree_sitter::Node, source: &str) -> (String, String) {
    let mut name = String::new();
    let mut ty = String::new();

    let mut cursor = param.walk();
    for child in param.children(&mut cursor) {
        match child.kind() {
            "identifier" | "shorthand_field_identifier" | "field_identifier" if name.is_empty() => {
                name = source[child.start_byte()..child.end_byte()].to_string();
            }
            "type_annotation" | "type_identifier" | "scoped_type_identifier" | "generic_type"
                if ty.is_empty() =>
            {
                ty = source[child.start_byte()..child.end_byte()].to_string();
            }
            _ => {}
        }
    }

    // Fallback: regex on full text
    if name.is_empty() || ty.is_empty() {
        let text = &source[param.start_byte()..param.end_byte()];
        if let Some(caps) = regex::Regex::new(r"([^:]+)\s*:\s*(.+)")
            .ok()
            .and_then(|re| re.captures(text))
        {
            if name.is_empty() {
                name = caps
                    .get(1)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
            }
            if ty.is_empty() {
                ty = caps
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
            }
        }
    }

    (name, ty)
}

/// Build a registry from a corpus directory by reading all positive files.
pub fn build_registry_from_dir(corpus_dir: &Path) -> CorpusSourceSinkRegistry {
    let mut positive_files = Vec::new();

    if let Ok(entries) = std::fs::read_dir(corpus_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.contains("_positive.") {
                if let Ok(source) = std::fs::read_to_string(&path) {
                    let ext = path
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("ts")
                        .to_string();
                    positive_files.push((source, ext));
                }
            }
        }
    }

    build_registry(&positive_files)
}

fn extract_sources_and_sinks(source: &str, ext_hint: &str) -> (Vec<String>, Vec<String>) {
    let mut sources = Vec::new();
    let mut sinks = Vec::new();
    let mut parser = tree_sitter::Parser::new();
    let lang_name = crate::parser::ext_to_language(ext_hint);
    let lang = crate::parser::ParserRegistry::get_language_by_name(lang_name).ok();
    let Some(lang) = lang else {
        return (sources, sinks);
    };
    parser.set_language(&lang).ok();
    let Some(tree) = parser.parse(source, None) else {
        return (sources, sinks);
    };
    let spec = spec_for_ext(ext_hint);
    extract_sources_and_sinks_recursive(tree.root_node(), source, &mut sources, &mut sinks, spec);
    (sources, sinks)
}

fn extract_sources_and_sinks_recursive(
    node: Node,
    source: &str,
    sources: &mut Vec<String>,
    sinks: &mut Vec<String>,
    spec: Option<&dyn frensense_lang::spec::LanguageSpec>,
) {
    let kind = node.kind();
    if kind == "pair" {
        if let Some(key) = node.child_by_field_name("key") {
            let key_name = &source[key.start_byte()..key.end_byte()];
            if key_name.starts_with('$') {
                sinks.push(key_name.to_string());
            }
        }
    }
    // Use spec-based classification for call nodes with fallback
    let is_call = spec
        .map(|s| matches!(s.classify(kind), frensense_lang::NodeRole::Call { .. }))
        .unwrap_or_else(|| kind == "call_expression");
    if is_call {
        if let Some(callee) = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("callee"))
            .or_else(|| node.child(0))
        {
            let full = source[callee.start_byte()..callee.end_byte()].to_string();
            if !full.is_empty() {
                sinks.push(full);
            }
        }
    }
    // Use spec-based classification for function nodes with fallback
    let is_fn = spec.map(|s| s.is_function_node(kind)).unwrap_or_else(|| {
        matches!(
            kind,
            "function_definition"
                | "function_declaration"
                | "arrow_function"
                | "method_definition"
                | "function_item"
                | "function_signature_item"
        )
    });
    if is_fn {
        if let Some(params) = node
            .child_by_field_name("parameters")
            .or_else(|| node.child_by_field_name("formal_parameters"))
        {
            let mut cursor = params.walk();
            for param in params.children(&mut cursor) {
                if matches!(param.kind(), "(" | ")" | "," | ";" | "self") {
                    continue;
                }
                let mut p_cursor = param.walk();
                for child in param.children(&mut p_cursor) {
                    match child.kind() {
                        "type_annotation"
                        | "type_identifier"
                        | "scoped_type_identifier"
                        | "generic_type" => {
                            let ty = source[child.start_byte()..child.end_byte()].trim();
                            if !ty.is_empty() {
                                let clean = ty.trim_start_matches(':').trim();
                                sources.push(clean.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            extract_sources_and_sinks_recursive(cursor.node(), source, sources, sinks, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

/// Split a raw callee expression string into `(short_name, qualified_name)`.
///
/// `short_name` is the final `.`-delimited segment (the method name).
/// `qualified_name` is the last two segments, used for context-aware matching
/// (e.g. `"db.collection(...).findOne"` → short=`"findOne"`, qualified=`"collection.findOne"`).
pub fn split_sink_name(raw: &str) -> (String, Option<String>) {
    // Strip call-argument suffixes like `(...)`
    let trimmed = if let Some(idx) = raw.find('(') {
        &raw[..idx]
    } else {
        raw
    };

    let parts: Vec<&str> = trimmed.split('.').collect();
    let short = parts
        .last()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let qualified = if parts.len() >= 2 {
        let last_two = &parts[parts.len() - 2..];
        // Skip if the penultimate segment contains parentheses (it's a chained call result)
        if !last_two[0].contains('(') {
            Some(format!("{}.{}", last_two[0].trim(), last_two[1].trim()))
        } else {
            None
        }
    } else {
        None
    };

    (short, qualified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sources_typescript() {
        let source = "function handler(req: Request, body: Json<User>) { }";
        let (types, _) = extract_sources_and_sinks(source, "ts");
        assert!(
            types.contains(&"Request".to_string()),
            "should find Request type"
        );
        assert!(
            types.contains(&"Json<User>".to_string()),
            "should find Json<User> type"
        );
    }

    #[test]
    fn test_extract_sources_rust() {
        let source = "fn handler(req: Query<Params>) -> Response {\n    let x = req;\n}";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut types = Vec::new();
        let (extracted, _) = extract_sources_and_sinks(source, "rs");
        types.extend(extracted);
        assert!(
            !types.is_empty(),
            "should find at least one type, got: {types:?}"
        );
    }

    #[test]
    fn test_extract_sinks_typescript() {
        let source = "function handler() { exec(cmd); eval(code); }";
        let (_, sinks) = extract_sources_and_sinks(source, "ts");
        assert!(sinks.contains(&"exec".to_string()), "should find exec sink");
        assert!(sinks.contains(&"eval".to_string()), "should find eval sink");
    }

    #[test]
    fn test_extract_sinks_member_expression() {
        let source = "function handler() { console.log(msg); document.write(html); }";
        let (_, sinks) = extract_sources_and_sinks(source, "ts");
        assert!(
            sinks.iter().any(|s| s.contains("console.log")),
            "should find console.log"
        );
        assert!(
            sinks.iter().any(|s| s.contains("document.write")),
            "should find document.write"
        );
    }

    #[test]
    fn test_registry_pruning() {
        let mut registry = CorpusSourceSinkRegistry::default();
        registry.source_types.insert("Request".to_string(), 3);
        registry.source_types.insert("OneOff".to_string(), 1);
        registry
            .sink_names
            .insert("exec".to_string(), (SinkCategory::CodeExecution, 5));
        registry
            .sink_names
            .insert("rare_sink".to_string(), (SinkCategory::Unknown, 1));

        registry.prune();

        assert!(registry.is_source_type("Request"));
        assert!(!registry.is_source_type("OneOff"));
        assert!(registry.is_sink("exec").is_some());
        assert!(registry.is_sink("rare_sink").is_none());
    }

    #[test]
    fn test_build_registry() {
        let files = vec![
            (
                "function handler(req: Request) { exec(req.query); }".to_string(),
                "ts".to_string(),
            ),
            (
                "function process(input: Request) { exec(input.data); }".to_string(),
                "ts".to_string(),
            ),
        ];
        let registry = build_registry(&files);
        assert!(
            registry.source_types.contains_key("Request"),
            "Request should be a source type, got: {:?}",
            registry.source_types
        );
        assert!(
            registry.sink_names.contains_key("exec"),
            "exec should be a sink, got: {:?}",
            registry.sink_names
        );
    }
}

pub fn taint_source_origin(pattern: &str) -> crate::data_flow::TaintOrigin {
    if pattern.contains("process.env") {
        crate::data_flow::TaintOrigin::Environment
    } else if pattern.contains("req.file") || pattern.contains("req.files") {
        crate::data_flow::TaintOrigin::FileSystem
    } else {
        crate::data_flow::TaintOrigin::UserInput
    }
}
