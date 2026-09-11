pub mod pdg;
// SPDX-License-Identifier: MIT

pub mod alias;
pub mod confidence;
pub mod cross_file;
pub mod engine;
pub mod normalization;
pub mod pii;
pub mod propagators;
pub mod reaching_defs;
pub mod resolver;
pub mod sanitizer;
pub mod taint_metrics;

pub use alias::AliasTracker;
pub use engine::DataFlowEngine;
pub use engine::FunctionTaintSummary;
pub use propagators::PropagatorRegistry;
pub use reaching_defs::DefState;
pub use resolver::ResolvedFunction;
pub use resolver::SymbolEntry;
pub use resolver::map_call_args_to_params;
pub use resolver::resolve_fn_definition;
pub use sanitizer::{SanitizerRegistry, SinkContext};

use rustc_hash::FxHashMap;

/// Shared parameter-name-to-taint-origin classifier used by both the CLI runner
/// and the semantic analysis pipeline. Consolidated here to eliminate the
/// duplicate (and slightly divergent) copies that previously lived in
/// `runner.rs` and `semantics/data_flow/cross_file.rs`.
///
/// `"name"` and `"data"` are intentionally excluded from the broad `UserInput`
/// list — they are extremely common in non-HTTP contexts (crypto functions,
/// display formatters, etc.). Use `classify_param_name_in_context` instead
/// when a `FileContext` (specifically `Environment`) is available.
pub fn classify_param_origin(name: &str) -> Option<TaintOrigin> {
    classify_param_origin_heuristic(name)
}

/// Taint-origin classifier that prefers the language spec (per-language,
/// type-aware) and falls back to the hardcoded heuristic.
pub fn classify_param_origin_with_spec(
    name: &str,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) -> Option<TaintOrigin> {
    if let Some(s) = spec {
        if let Some(origin) = s.classify_param_taint(Some(name), None) {
            return Some(match origin {
                frensense_lang::TaintOrigin::UserInput => TaintOrigin::UserInput,
                frensense_lang::TaintOrigin::EnvVariable => TaintOrigin::Environment,
                frensense_lang::TaintOrigin::FileSystem => TaintOrigin::FileSystem,
                frensense_lang::TaintOrigin::Database => TaintOrigin::Database,
                frensense_lang::TaintOrigin::ExternalService => TaintOrigin::Network,
            });
        }
    }
    classify_param_origin_heuristic(name)
}

/// Heuristic name-based taint origin classification.
///
/// The names `"name"` and `"data"` are intentionally excluded here — they
/// are extremely common in non-HTTP contexts. Use
/// `classify_param_name_in_context` when a `FileContext` is available.
fn classify_param_origin_heuristic(name: &str) -> Option<TaintOrigin> {
    let lower = name.to_lowercase();
    if matches!(
        lower.as_str(),
        "req"
            | "request"
            | "event"
            | "ctx"
            | "context"
            | "payload"
            | "input"
            | "body"
            | "query"
            | "params"
            | "searchparams"
            | "args"
            | "cmd"
            | "url"
            | "path"
            | "file"
            | "userid"
            | "user_id"
            | "uid"
            | "token"
            | "jwt"
            | "email"
            | "password"
            | "passwd"
            | "username"
            | "user_name"
            | "login"
            | "message"
            | "text"
            | "html"
            | "ssn"
            | "dob"
            | "address"
            | "bankacc"
            | "bankrouting"
            | "firstname"
            | "lastname"
    ) {
        return Some(TaintOrigin::UserInput);
    }
    if matches!(
        lower.as_str(),
        "env" | "config" | "settings" | "conf" | "options" | "opts" | "cfg"
    ) {
        return Some(TaintOrigin::Environment);
    }
    if matches!(
        lower.as_str(),
        "db" | "conn" | "connection" | "pool" | "row" | "record" | "result" | "results"
    ) {
        return Some(TaintOrigin::Database);
    }
    if matches!(
        lower.as_str(),
        "socket" | "ws" | "stream" | "client" | "server" | "tcp" | "udp" | "peer"
    ) {
        return Some(TaintOrigin::Network);
    }
    if matches!(
        lower.as_str(),
        "fd" | "filepath" | "filename" | "buf" | "reader" | "src"
    ) {
        return Some(TaintOrigin::FileSystem);
    }
    None
}

/// Context-aware version of `classify_param_origin`.
///
/// The names `"name"` and `"data"` are only treated as `UserInput` when
/// the enclosing file is a `RouteHandler`. In all other environments they
/// fall through to `None` (no taint), avoiding phantom origins in crypto,
/// formatters, and other non-HTTP code.
pub fn classify_param_name_in_context(
    name: &str,
    env: Option<&crate::context::Environment>,
) -> Option<TaintOrigin> {
    classify_param_name_in_context_with_spec(name, env, None)
}

/// Context-aware version of `classify_param_origin` that also consults the
/// language spec.  When a spec is available its per-language, type-aware
/// classification is tried first.
pub fn classify_param_name_in_context_with_spec(
    name: &str,
    env: Option<&crate::context::Environment>,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) -> Option<TaintOrigin> {
    if let Some(origin) = classify_param_origin_with_spec(name, spec) {
        return Some(origin);
    }
    let lower = name.to_lowercase();
    if matches!(
        lower.as_str(),
        "name" | "data" | "value" | "threshold" | "stocks" | "funds" | "bonds"
    ) {
        if env == Some(&crate::context::Environment::RouteHandler) {
            return Some(TaintOrigin::UserInput);
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintOrigin {
    UserInput,
    Environment,
    Database,
    Network,
    FileSystem,
    Custom(String),
}

impl std::fmt::Display for TaintOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserInput => write!(f, "user_input"),
            Self::Environment => write!(f, "environment"),
            Self::Database => write!(f, "database"),
            Self::Network => write!(f, "network"),
            Self::FileSystem => write!(f, "file_system"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl From<&str> for TaintOrigin {
    fn from(s: &str) -> Self {
        match s {
            "user_input" | "user" => Self::UserInput,
            "environment" | "env" => Self::Environment,
            "database" | "db" => Self::Database,
            "network" | "net" => Self::Network,
            "file_system" | "fs" => Self::FileSystem,
            _ => Self::Custom(s.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaintRegistry {
    scopes: Vec<FxHashMap<String, TaintOrigin>>,
    symbol_ranges: Vec<FxHashMap<String, (usize, usize)>>,
    field_taint: Vec<FxHashMap<(String, String), TaintOrigin>>,
}

impl Default for TaintRegistry {
    fn default() -> Self {
        Self {
            scopes: vec![FxHashMap::default()],
            symbol_ranges: vec![FxHashMap::default()],
            field_taint: vec![FxHashMap::default()],
        }
    }
}

impl TaintRegistry {
    pub fn push_scope(&mut self) {
        self.scopes.push(FxHashMap::default());
        self.symbol_ranges.push(FxHashMap::default());
        self.field_taint.push(FxHashMap::default());
    }

    /// CONSERVATIVE: conditional sanitization does not untaint.
    pub fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
            self.symbol_ranges.pop();
            self.field_taint.pop();
        }
    }

    pub fn taint_field(&mut self, var: &str, field: &str, origin: TaintOrigin) {
        if let Some(scope) = self.field_taint.last_mut() {
            scope.insert((var.to_string(), field.to_string()), origin);
        }
    }

    pub fn get_field_origin(&self, var: &str, field: &str) -> Option<TaintOrigin> {
        let key = (var.to_string(), field.to_string());
        for scope in self.field_taint.iter().rev() {
            if let Some(origin) = scope.get(&key) {
                return Some(origin.clone());
            }
        }
        None
    }

    pub fn get_any_field_origin(&self, var: &str) -> Option<TaintOrigin> {
        for scope in self.field_taint.iter().rev() {
            for ((v, _), origin) in scope {
                if v == var {
                    return Some(origin.clone());
                }
            }
        }
        None
    }

    pub fn taint(&mut self, var: &str, origin: TaintOrigin) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(var.to_string(), origin);
        }
    }

    pub fn register_symbol(&mut self, name: &str, start_byte: usize, end_byte: usize) {
        if let Some(scope) = self.symbol_ranges.last_mut() {
            scope.insert(name.to_string(), (start_byte, end_byte));
        }
    }

    pub fn get_origin(&self, var: &str) -> Option<TaintOrigin> {
        for scope in self.scopes.iter().rev() {
            if let Some(origin) = scope.get(var) {
                return Some(origin.clone());
            }
        }
        None
    }

    pub fn find_symbol_range(&self, name: &str) -> Option<(usize, usize)> {
        for scope in self.symbol_ranges.iter().rev() {
            if let Some(range) = scope.get(name) {
                return Some(*range);
            }
        }
        None
    }

    pub fn is_tainted(&self, var: &str) -> bool {
        self.get_origin(var).is_some() || self.get_any_field_origin(var).is_some()
    }

    pub fn untaint(&mut self, var: &str) {
        for scope in self.scopes.iter_mut().rev() {
            if scope.remove(var).is_some() {
                break;
            }
        }
    }

    pub fn has_any_tainted(&self) -> bool {
        self.scopes.iter().any(|scope| !scope.is_empty())
            || self.field_taint.iter().any(|scope| !scope.is_empty())
    }
}
