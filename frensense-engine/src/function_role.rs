// SPDX-License-Identifier: MIT

//! Function role classifier — identifies what a function DOES from its fingerprint.
//!
//! A lightweight structural classifier that assigns one of 5 roles with zero
//! corpus lookup.  Used as a pre-filter before scoring: if the candidate's role
//! is incompatible with the pattern's role, the pattern can't possibly match.

use crate::fingerprint::FunctionFingerprint;
use crate::import_resolver::ImportMap;

use frensense_lang::LanguageSpec;

/// High-level role a function plays in the codebase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionRole {
    /// Express/Fastify/Hono route handler: params include req/res, calls res.*
    HttpHandler,
    /// Reads or writes a database: calls query/execute/prepare/raw
    DbQuery,
    /// Spawns or executes a system command: calls exec/spawn/system
    ShellExecutor,
    /// Pure data transformation: no control flow, no API calls, just ngrams
    DataTransformer,
    /// None of the above
    Unknown,
}

/// Known Express/HTTP response method names (last-segment form) across languages.
const HTTP_METHODS: &[&str] = &[
    // JS/TS
    "json",
    "send",
    "redirect",
    "status",
    "render",
    "end",
    "write",
    "setheader",
    "cookie",
    "clearcookie",
    "type",
    "format",
    "attachment",
    // Go
    "writeheader",
    "setcookie",
    "writestring",
    "servehttp",
    // Rust
    "ok",
    "created",
    "internal_server_error",
    "into_response",
    "content_type",
    "body",
    "finish",
    // Java/C#
    "badrequest",
    "notfound",
    "addcookie",
    "setstatus",
    "view",
];

/// Names that mark a function parameter as request-shaped.
const REQUEST_PARAM_NAMES: &[&str] = &["req", "request", "ctx", "context", "event", "c"];

/// Route-registration call patterns that indicate the function is an
/// HTTP handler definition, not a helper that merely calls response methods.
const ROUTE_REGISTRATIONS: &[&str] = &[
    "app.get",
    "app.post",
    "app.put",
    "app.delete",
    "app.patch",
    "app.use",
    "app.all",
    "router.get",
    "router.post",
    "router.put",
    "router.delete",
    "router.patch",
    "route.get",
    "route.post",
    "route.put",
    "route.delete",
    "server.get",
    "server.post",
    "server.put",
    "server.delete",
    "fastify.get",
    "fastify.post",
    "fastify.put",
    "fastify.delete",
    "hono.get",
    "hono.post",
    "hono.put",
    "hono.delete",
];

/// Known database query API names across languages.
const DB_API: &[&str] = &[
    // Generic / JS
    "query",
    "execute",
    "prepare",
    "raw",
    "find",
    "findone",
    "findmany",
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
    // Go
    "queryrow",
    "exec",
    "begin",
    "first",
    "updates",
    // Rust
    "fetch_one",
    "fetch_optional",
    "fetch_all",
    "load",
    "get_result",
    "insert_into",
    // Java/C#
    "persist",
    "merge",
    "remove",
    "savechanges",
    "add",
];

/// Known shell execution API names across languages.
const SHELL_API: &[&str] = &[
    // Generic / JS
    "exec",
    "spawn",
    "execfile",
    "execsync",
    "spawnsync",
    "system",
    "popen",
    "run",
    "cmd",
    "sh",
    "bash",
    // Go
    "command",
    "output",
    "combinedoutput",
    "start",
    // Rust
    "command::new",
    "status",
    // Java/C#
    "getruntime().exec",
    "processbuilder",
    "process.start",
];

/// Classify a function's role from its fingerprint.
///
/// Uses only the fingerprint data (no AST access needed):
/// - `api_calls` / `api_call_segments` for method-level detection
/// - `signature_ngrams` / `param_type_ngrams` for parameter shape
///
/// The checks are ordered by priority — HttpHandler is checked first
/// because its signal (res.json/send/redirect) is the strongest.
pub fn classify_role(fp: &FunctionFingerprint) -> FunctionRole {
    classify_role_with_imports(fp, None, None)
}

/// Like `classify_role` but also uses the per-file import map to resolve
/// ambiguous type annotations (e.g. `Request` → `express.Request`).
///
/// When an import map is available, a function whose parameter type
/// annotations (like `Request` or `Response`) are confirmed to come from
/// an HTTP framework package gets an additional HttpHandler signal,
/// reducing false negatives from unconventional parameter naming.
///
/// When a language spec is available, its methods are consulted first for
/// response names, request params, route registrations, DB APIs, and shell
/// APIs, with the hardcoded lists as fallback.
pub fn classify_role_with_imports(
    fp: &FunctionFingerprint,
    import_map: Option<&ImportMap>,
    spec: Option<&dyn LanguageSpec>,
) -> FunctionRole {
    let _all_calls = &fp.raw_call_names;

    if is_http_handler(fp, import_map, spec) {
        return FunctionRole::HttpHandler;
    }

    if is_shell_executor(fp, spec) {
        return FunctionRole::ShellExecutor;
    }

    if is_db_query(fp, spec) {
        return FunctionRole::DbQuery;
    }

    if fp.control_flow_hashes.is_empty()
        && fp.api_calls.is_empty()
        && fp.api_call_segments.is_empty()
    {
        return FunctionRole::DataTransformer;
    }

    FunctionRole::Unknown
}

/// Check if fingerprint matches an HTTP request/response handler.
///
/// Requires at least **two** of the following signals:
///
///   (a) Response call — function calls `res.send`, `.json`, `.redirect`, etc.
///   (b) Request-shaped parameters — param names include `req`, `request`, `ctx`, etc.
///   (c) Route-registration context — function body contains `app.get`, `router.post`, etc.
///   (d) [import-aware] Typed parameters — `type_usages` contain `Request`/`Response`
///       confirmed by the import map to come from an HTTP framework package.
///   (e) Routing decorator — function has `@Get`, `@Post`, `@Put`, etc. (NestJS / tsoa / type-graphql)
///   (f) Route registration — function is referenced in `app.get('/path', fn)`
///       or is an inline arrow passed to a router method.
///   (g) File export — function is a file-level export matching framework conventions
///       (Next.js App/Pages Router, SvelteKit, Cloudflare Workers, AWS Lambda).
fn is_http_handler(
    fp: &FunctionFingerprint,
    import_map: Option<&ImportMap>,
    spec: Option<&dyn LanguageSpec>,
) -> bool {
    let mut signals = 0u8;

    let has_response = fp.raw_call_names.iter().any(|c| {
        let lower = c.to_lowercase();
        // Prefer spec-provided names when available
        if let Some(s) = spec {
            if s.response_method_names().iter().any(|m| lower.ends_with(m)) {
                return true;
            }
        }
        HTTP_METHODS.iter().any(|m| lower.ends_with(m))
    });
    if has_response {
        signals += 1;
    }

    let has_request_param = fp.param_names.iter().any(|n| {
        let lower = n.to_lowercase();
        if let Some(s) = spec {
            if s.request_param_names().iter().any(|p| lower == *p) {
                return true;
            }
        }
        REQUEST_PARAM_NAMES.iter().any(|p| lower == *p)
    });
    if has_request_param {
        signals += 1;
    }

    let has_route_reg = fp.raw_call_names.iter().any(|c| {
        let lower = c.to_lowercase();
        if let Some(s) = spec {
            if s.route_registration_patterns()
                .iter()
                .any(|r| lower.ends_with(r))
            {
                return true;
            }
        }
        ROUTE_REGISTRATIONS.iter().any(|r| lower.ends_with(r))
    });
    if has_route_reg {
        signals += 1;
    }

    // Type-annotation signal (import-map-aware)
    let has_typed_params = import_map.is_some_and(|m| m.has_http_entry_point(&fp.type_usages));
    if has_typed_params {
        signals += 1;
    }

    // Decorator signal: NestJS/routing-controllers/tsoa/type-graphql methods.
    // Unambiguous on its own - a @Controller/@Get/@Post method is an HTTP
    // handler even with no req param / res.send() / app.get() (NestJS
    // resolves the request internally). Worth two signals so a bare
    // decorated method still clears the threshold.
    if fp.has_http_decorator {
        signals += 2;
    }

    // Route registration signal: `app.get('/path', fn)` or inline arrow
    if fp.is_registered_handler {
        signals += 1;
    }

    // File export signal: Next.js App Router, SvelteKit, Cloudflare Workers,
    // AWS Lambda. Unambiguous - an exported named handler function is by
    // definition an HTTP entry point worth two signals.
    if fp.export_handler_kind.is_some() {
        signals += 2;
    }

    signals >= 2
}

/// Check if fingerprint matches a shell executor.
fn is_shell_executor(fp: &FunctionFingerprint, spec: Option<&dyn LanguageSpec>) -> bool {
    fp.raw_call_names.iter().any(|c| {
        let lower = c.to_lowercase();
        if let Some(s) = spec {
            if s.shell_api_method_names()
                .iter()
                .any(|api| lower.ends_with(api))
            {
                return true;
            }
        }
        SHELL_API.iter().any(|api| lower.ends_with(api))
    })
}

/// Check if fingerprint matches a database query function.
fn is_db_query(fp: &FunctionFingerprint, spec: Option<&dyn LanguageSpec>) -> bool {
    fp.raw_call_names.iter().any(|c| {
        let lower = c.to_lowercase();
        if let Some(s) = spec {
            if s.db_api_method_names()
                .iter()
                .any(|api| lower.ends_with(api))
            {
                return true;
            }
        }
        DB_API.iter().any(|api| lower.ends_with(api))
    })
}

/// Check if two roles are incompatible (cannot be the same function).
///
/// - An HttpHandler can NEVER be a ShellExecutor or DbQuery
/// - A DataTransformer is compatible with everything (too generic)
/// - Unknown is compatible with everything (no information)
pub fn roles_are_incompatible(role_a: FunctionRole, role_b: FunctionRole) -> bool {
    use FunctionRole::*;
    if role_a == Unknown
        || role_b == Unknown
        || role_a == DataTransformer
        || role_b == DataTransformer
    {
        return false;
    }
    role_a != role_b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fp(
        api_calls: Vec<u64>,
        api_call_segments: Vec<u64>,
        control_flow: Vec<u64>,
        structural: Vec<u64>,
        sig: Vec<u64>,
        param_types: Vec<u64>,
        raw_call_names: Vec<String>,
        param_names: Vec<String>,
    ) -> FunctionFingerprint {
        FunctionFingerprint {
            file_path: String::new(),
            function_name: String::new(),
            line: 0,
            language: String::new(),
            ngram_hashes: Vec::new(),
            weighted_ngram_hashes: Default::default(),
            signature_ngrams: sig,
            param_type_ngrams: param_types,
            name_segments: Vec::new(),
            structural_markers: structural,
            type_usages: Vec::new(),
            comment_density: 0.0,
            semantic_markers: Vec::new(),
            skeleton: Vec::new(),
            skeleton_hashes: Vec::new(),
            control_flow_hashes: control_flow,
            control_flow_sequence: Vec::new(),
            api_calls,
            api_call_segments,
            property_accesses: Vec::new(),
            motif_hashes: Vec::new(),
            data_flow_path_hashes: Vec::new(),
            raw_call_names,
            param_names,
            tainted_api_calls: Vec::new(),
            config_literal_hashes: Vec::new(),
            argument_call_types: Vec::new(),
            literal_pattern_hashes: Vec::new(),
            has_http_decorator: false,
            is_registered_handler: false,
            export_handler_kind: None,
        }
    }

    #[test]
    fn test_http_handler_classification() {
        // Two signals: response call + request-shaped param → HttpHandler
        let fp = make_fp(
            vec![1, 2, 3],                              // api_calls
            vec![4, 5],                                 // segments
            vec![10, 11],                               // control_flow
            vec![20, 21, 22, 23, 24, 25],               // structural
            vec![30, 31],                               // sig
            vec![40, 41],                               // param_types
            vec!["res.send".to_string()],               // raw_call_names — signal (a)
            vec!["req".to_string(), "res".to_string()], // param_names — signal (b)
        );
        assert_eq!(classify_role(&fp), FunctionRole::HttpHandler);
    }

    #[test]
    fn test_http_handler_rejects_helper_with_only_response() {
        // Helper like sendError(res, msg): only signal (a), no req param, no route reg
        let fp = make_fp(
            vec![1, 2],
            vec![],
            vec![10],
            vec![20, 21, 22, 23, 24, 25],
            vec![30],
            vec![],
            vec!["res.send".to_string()], // raw_call_names — signal (a) only
            vec![],
        );
        assert_eq!(classify_role(&fp), FunctionRole::Unknown);
    }

    #[test]
    fn test_http_handler_route_registration() {
        // Two signals: response call + route registration
        let fp = make_fp(
            vec![1, 2],
            vec![],
            vec![10],
            vec![20, 21, 22, 23, 24, 25],
            vec![30],
            vec![],
            vec!["res.send".to_string(), "app.get".to_string()],
            vec![],
        );
        assert_eq!(classify_role(&fp), FunctionRole::HttpHandler);
    }

    #[test]
    fn test_decorator_only_handler_is_http_handler() {
        // NestJS-style: `@Get('/users') async getUsers() { return this.svc.findAll(); }`
        // has ONLY the HTTP decorator signal — no req/res params, no res.send(),
        // no app.get() route registration. The decorator must count as two
        // signals so it still clears the >= 2 threshold.
        let mut fp = make_fp(
            vec![],
            vec![],
            vec![10],
            vec![20, 21, 22, 23, 24, 25],
            vec![30],
            vec![],
            vec![],
            vec![],
        );
        fp.has_http_decorator = true;
        assert_eq!(classify_role(&fp), FunctionRole::HttpHandler);
    }

    #[test]
    fn test_exported_handler_only_is_http_handler() {
        // Next.js/SvelteKit/CF Worker style: just an exported named handler.
        let mut fp = make_fp(
            vec![],
            vec![],
            vec![10],
            vec![20, 21, 22, 23, 24, 25],
            vec![30],
            vec![],
            vec![],
            vec![],
        );
        fp.export_handler_kind = Some(crate::export_matcher::ExportHandlerKind::LambdaHandler);
        assert_eq!(classify_role(&fp), FunctionRole::HttpHandler);
    }

    #[test]
    fn test_shell_executor_classification() {
        // ShellExecutor: has exec in raw_call_names → matches SHELL_API
        let fp = make_fp(
            vec![1, 2], // api_calls
            vec![],
            vec![10],                     // control_flow
            vec![20, 21, 22, 23, 24, 25], // structural
            vec![30],
            vec![40],
            vec!["exec".to_string()], // raw_call_names
            vec![],
        );
        assert_eq!(classify_role(&fp), FunctionRole::ShellExecutor);
    }

    #[test]
    fn test_data_transformer_classification() {
        // DataTransformer: no API calls, no control flow, no raw_call_names
        let fp = make_fp(
            vec![],
            vec![],
            vec![],
            vec![20, 21, 22],
            vec![30],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(classify_role(&fp), FunctionRole::DataTransformer);
    }

    #[test]
    fn test_roles_incompatible() {
        assert!(roles_are_incompatible(
            FunctionRole::HttpHandler,
            FunctionRole::ShellExecutor
        ));
        assert!(roles_are_incompatible(
            FunctionRole::ShellExecutor,
            FunctionRole::HttpHandler
        ));
        assert!(roles_are_incompatible(
            FunctionRole::HttpHandler,
            FunctionRole::DbQuery
        ));
        assert!(!roles_are_incompatible(
            FunctionRole::HttpHandler,
            FunctionRole::HttpHandler
        ));
        assert!(!roles_are_incompatible(
            FunctionRole::Unknown,
            FunctionRole::ShellExecutor
        ));
    }
}
