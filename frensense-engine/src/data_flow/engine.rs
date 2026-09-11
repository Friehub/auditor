// SPDX-License-Identifier: MIT

use rustc_hash::FxHashMap;

use crate::data_flow::TaintOrigin;
use crate::data_flow::TaintRegistry;

#[derive(Debug, Clone)]
pub struct FunctionTaintSummary {
    pub propagates_return: bool,
    pub tainted_params: FxHashMap<usize, TaintOrigin>,
    pub return_origins: Vec<TaintOrigin>,
}

#[derive(Debug, Clone, Default)]
pub struct DataFlowEngine {
    summaries: FxHashMap<String, FxHashMap<String, FunctionTaintSummary>>,
    global_taint: FxHashMap<String, FxHashMap<String, TaintOrigin>>,
    global_field_taint: FxHashMap<String, FxHashMap<(String, String), TaintOrigin>>,
}

impl DataFlowEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_global_taint(&mut self, file_path: &str, var_name: &str, origin: TaintOrigin) {
        self.global_taint
            .entry(file_path.to_string())
            .or_default()
            .insert(var_name.to_string(), origin);
    }

    pub fn register_global_field_taint(
        &mut self,
        file_path: &str,
        var_name: &str,
        field: &str,
        origin: TaintOrigin,
    ) {
        self.global_field_taint
            .entry(file_path.to_string())
            .or_default()
            .insert((var_name.to_string(), field.to_string()), origin);
    }

    pub fn get_global_taint(&self, file_path: &str, var_name: &str) -> Option<TaintOrigin> {
        self.global_taint.get(file_path)?.get(var_name).cloned()
    }

    pub fn get_global_field_taint(
        &self,
        file_path: &str,
        var_name: &str,
        field: &str,
    ) -> Option<TaintOrigin> {
        self.global_field_taint
            .get(file_path)?
            .get(&(var_name.to_string(), field.to_string()))
            .cloned()
    }

    pub fn seed_registry_from_globals(&self, file_path: &str, registry: &mut TaintRegistry) {
        if let Some(taints) = self.global_taint.get(file_path) {
            for (var, origin) in taints {
                registry.taint(var, origin.clone());
            }
        }
        if let Some(field_taints) = self.global_field_taint.get(file_path) {
            for ((var, field), origin) in field_taints {
                registry.taint_field(var, field, origin.clone());
            }
        }
    }

    pub fn cache_summary(
        &mut self,
        file_path: &str,
        function_name: &str,
        summary: FunctionTaintSummary,
    ) {
        self.summaries
            .entry(file_path.to_string())
            .or_default()
            .insert(function_name.to_string(), summary);
    }

    pub fn get_summary(
        &self,
        file_path: &str,
        function_name: &str,
    ) -> Option<&FunctionTaintSummary> {
        self.summaries.get(file_path)?.get(function_name)
    }

    pub fn cache_taint_summary_from_registry(
        &mut self,
        file_path: &str,
        function_name: &str,
        registry: &TaintRegistry,
        param_names: &[String],
        has_return_taint: bool,
        return_origins: Vec<TaintOrigin>,
    ) {
        let mut tainted_params = FxHashMap::default();
        for (idx, name) in param_names.iter().enumerate() {
            if let Some(origin) = registry.get_origin(name) {
                tainted_params.insert(idx, origin);
            }
        }
        self.cache_summary(
            file_path,
            function_name,
            FunctionTaintSummary {
                propagates_return: has_return_taint,
                tainted_params,
                return_origins,
            },
        );
    }

    pub fn invalidate_file(&mut self, file_path: &str) {
        self.summaries.remove(file_path);
        self.global_taint.remove(file_path);
        self.global_field_taint.remove(file_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_taint_seed() {
        let mut engine = DataFlowEngine::new();
        engine.register_global_taint("a.rs", "DB_POOL", TaintOrigin::Database);
        engine.register_global_field_taint(
            "a.rs",
            "CONFIG",
            "secret_key",
            TaintOrigin::Environment,
        );

        let mut registry = TaintRegistry::default();
        engine.seed_registry_from_globals("a.rs", &mut registry);

        assert!(registry.is_tainted("DB_POOL"));
        assert_eq!(registry.get_origin("DB_POOL"), Some(TaintOrigin::Database));
        assert!(registry.is_tainted("CONFIG"));
        assert_eq!(
            registry.get_field_origin("CONFIG", "secret_key"),
            Some(TaintOrigin::Environment)
        );
    }

    #[test]
    fn test_global_taint_scoped_to_file() {
        let mut engine = DataFlowEngine::new();
        engine.register_global_taint("a.rs", "POOL", TaintOrigin::Database);

        let mut registry = TaintRegistry::default();
        engine.seed_registry_from_globals("b.rs", &mut registry);

        assert!(!registry.is_tainted("POOL"));
    }

    #[test]
    fn test_cache_invalidation() {
        let mut engine = DataFlowEngine::new();
        engine.cache_summary(
            "a.rs",
            "foo",
            FunctionTaintSummary {
                propagates_return: true,
                tainted_params: FxHashMap::default(),
                return_origins: vec![TaintOrigin::UserInput],
            },
        );
        engine.register_global_taint("a.rs", "X", TaintOrigin::Network);

        engine.invalidate_file("a.rs");

        assert!(engine.get_summary("a.rs", "foo").is_none());
        assert!(engine.get_global_taint("a.rs", "X").is_none());
    }
}
