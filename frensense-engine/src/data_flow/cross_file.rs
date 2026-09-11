// SPDX-License-Identifier: MIT

use crate::data_flow::TaintOrigin;
#[cfg(feature = "full-analysis")]
use crate::graph::{EdgeKind, SemanticGraph};
use crate::symbols::Symbol;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;

/// Maximum propagation depth through the call graph for transitive taint.
/// A depth of 5 covers typical layered architectures (handler → service → service → repository → DB).
const PROPAGATE_MAX_DEPTH: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CrossFileTaint {
    pub source_file: String,
    pub sink_file: String,
    pub source_symbol: String,
    pub sink_symbol: String,
    pub origin: TaintOrigin,
    pub path_length: usize,
}

#[derive(Debug, Clone, Default)]
pub struct CrossFileTaintResolver {
    call_graph: FxHashMap<String, Vec<String>>,
    reverse_call_graph: FxHashMap<String, Vec<String>>,
    module_map: FxHashMap<String, Vec<String>>,
    /// Key: `"{file_path}:{symbol_name}"` — O(1) lookup.
    /// Previously keyed by `(symbol, file)` tuple which required O(n) scan in `find_taint_source`.
    exposed_taint: FxHashMap<String, TaintOrigin>,
}

impl CrossFileTaintResolver {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "full-analysis")]
    pub fn build_from_symbols(&mut self, all_symbols: &[&Symbol], graph: &SemanticGraph) {
        for sym in all_symbols {
            let sym_key = format!("{}:{}", sym.file_path, sym.name);
            let callees = graph
                .find_nodes(&sym.name)
                .into_iter()
                .flat_map(|node_id| graph.neighbors_of(node_id, EdgeKind::Calls))
                .filter_map(|callee_id| graph.get_symbol(callee_id))
                .map(|callee| format!("{}:{}", callee.file_path, callee.name));

            let callee_list: Vec<String> = callees.collect();
            if !callee_list.is_empty() {
                self.call_graph
                    .entry(sym_key.clone())
                    .or_default()
                    .extend(callee_list.clone());
                for callee in &callee_list {
                    self.reverse_call_graph
                        .entry(callee.clone())
                        .or_default()
                        .push(sym_key.clone());
                }
            }
        }
    }

    pub fn register_exposed_taint(
        &mut self,
        symbol_key: &str,
        file_path: &str,
        origin: TaintOrigin,
    ) {
        // Key is "{file_path}:{symbol_key}" for O(1) lookup in find_taint_source.
        self.exposed_taint
            .insert(format!("{file_path}:{symbol_key}"), origin);
    }

    /// Propagate taint forward through the call graph.
    ///
    /// If `handleOrder` is a taint source and calls `processOrder`, then
    /// `processOrder` transitively returns/contains tainted data and should
    /// also be registered as a source.  Without this, multi-hop chains
    /// (HttpHandler → DataTransformer → DbQuery) fail to resolve.
    ///
    /// BFS forward from each registered source up to `PROPAGATE_MAX_DEPTH`.
    /// Call this once after all initial `register_exposed_taint` calls.
    pub fn propagate_taint(&mut self, sanitizers: Option<&crate::data_flow::SanitizerRegistry>) {
        // exposed_taint is now keyed by "{file}:{symbol}" directly — no reconstruction needed.
        let seeds: Vec<(String, TaintOrigin)> = self
            .exposed_taint
            .iter()
            .map(|(key, origin)| (key.clone(), origin.clone()))
            .collect();

        for (seed_key, origin) in &seeds {
            let mut visited = FxHashSet::default();
            let mut queue = VecDeque::new();
            queue.push_back((seed_key.clone(), 0));
            visited.insert(seed_key.clone());

            while let Some((current, depth)) = queue.pop_front() {
                if depth >= PROPAGATE_MAX_DEPTH {
                    continue;
                }

                if let Some(callees) = self.call_graph.get(&current) {
                    for callee in callees {
                        if let Some(reg) = sanitizers {
                            let callee_name = callee.split(':').last().unwrap_or(callee.as_str());
                            if reg.is_full_sanitizer(callee_name) {
                                continue;
                            }
                        }
                        if visited.insert(callee.clone()) {
                            // Register the intermediate function as a taint source
                            // using the flat "{file}:{symbol}" key format.
                            self.exposed_taint
                                .entry(callee.clone())
                                .or_insert_with(|| origin.clone());
                            queue.push_back((callee.clone(), depth + 1));
                        }
                    }
                }
            }
        }
    }

    pub fn resolve_taint(
        &self,
        sink_symbol: &str,
        sink_file: &str,
        max_depth: usize,
    ) -> Vec<CrossFileTaint> {
        let sink_key = format!("{sink_file}:{sink_symbol}");
        let mut results = Vec::new();
        let mut visited = FxHashSet::default();
        let mut queue = VecDeque::new();
        queue.push_back((sink_key.clone(), 0));
        visited.insert(sink_key.clone());

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            if let Some((origin, source_key)) = self.find_taint_source(&current) {
                let mut source_file = source_key.clone();
                let mut source_symbol = source_key.clone();
                if let Some(idx) = source_key.find(':') {
                    source_file = source_key[..idx].to_string();
                    source_symbol = source_key[idx + 1..].to_string();
                }
                results.push(CrossFileTaint {
                    source_file,
                    sink_file: sink_file.to_string(),
                    source_symbol,
                    sink_symbol: sink_symbol.to_string(),
                    origin,
                    path_length: depth + 1,
                });
            }

            if let Some(callers) = self.reverse_call_graph.get(&current) {
                for caller in callers {
                    if visited.insert(caller.clone()) {
                        queue.push_back((caller.clone(), depth + 1));
                    }
                }
            }

            if let Some(imports) = self.module_map.get(&current) {
                for imp in imports {
                    if visited.insert(imp.clone()) {
                        queue.push_back((imp.clone(), depth + 1));
                    }
                }
            }
        }

        results
    }

    fn find_taint_source(&self, key: &str) -> Option<(TaintOrigin, String)> {
        // O(1) direct lookup — the key is stored as "{file_path}:{symbol_name}".
        self.exposed_taint
            .get(key)
            .map(|origin| (origin.clone(), key.to_string()))
    }

    pub fn all_taint_paths(&self, max_depth: usize) -> Vec<CrossFileTaint> {
        let mut results = Vec::new();
        for sink_key in self.call_graph.keys() {
            if let Some(idx) = sink_key.find(':') {
                let sink_file = &sink_key[..idx];
                let sink_symbol = &sink_key[idx + 1..];
                let paths = self.resolve_taint(sink_symbol, sink_file, max_depth);
                results.extend(paths);
            }
        }
        results
    }

    pub fn callers_of(&self, symbol_key: &str) -> Vec<&str> {
        self.reverse_call_graph
            .get(symbol_key)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn callees_of(&self, symbol_key: &str) -> Vec<&str> {
        self.call_graph
            .get(symbol_key)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

#[cfg(feature = "full-analysis")]
pub fn build_resolver(all_symbols: &[&Symbol], graph: &SemanticGraph) -> CrossFileTaintResolver {
    let mut resolver = CrossFileTaintResolver::new();
    resolver.build_from_symbols(all_symbols, graph);
    resolver
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileId;
    #[cfg(feature = "full-analysis")]
    use crate::graph::SemanticGraph;
    use crate::symbols::{Symbol, SymbolKind};

    fn make_symbol(name: &str, file: &str) -> Symbol {
        Symbol {
            name: name.to_string(),
            kind: SymbolKind::Function,
            start_byte: 0,
            end_byte: 0,
            file_path: file.to_string(),
            file_id: FileId(0),
            line: 1,
            column: 1,
            end_line: 1,
        }
    }

    #[test]
    fn test_propagate_taint_chain() {
        let mut resolver = CrossFileTaintResolver::new();
        // Build a call graph: source → intermediate → sink
        resolver.call_graph.insert(
            "a.rs:source".to_string(),
            vec!["a.rs:intermediate".to_string()],
        );
        resolver.call_graph.insert(
            "a.rs:intermediate".to_string(),
            vec!["a.rs:sink".to_string()],
        );
        resolver.reverse_call_graph.insert(
            "a.rs:intermediate".to_string(),
            vec!["a.rs:source".to_string()],
        );
        resolver.reverse_call_graph.insert(
            "a.rs:sink".to_string(),
            vec!["a.rs:intermediate".to_string()],
        );

        // Seed only the source
        resolver.register_exposed_taint("source", "a.rs", TaintOrigin::UserInput);

        // With max_depth=1, backward BFS from sink reaches intermediate but not source
        // → no path found without propagation
        let before = resolver.resolve_taint("sink", "a.rs", 1);
        assert!(
            before.is_empty(),
            "with depth=1, multi-hop chain should fail without propagation"
        );

        // After propagation: intermediate is transitively seeded
        resolver.propagate_taint(None);
        assert!(
            resolver.exposed_taint.contains_key("a.rs:intermediate"),
            "propagate_taint should register intermediate as a taint source"
        );

        // Now with depth=1, backward BFS finds intermediate as a source
        let after = resolver.resolve_taint("sink", "a.rs", 1);
        assert!(
            !after.is_empty(),
            "propagate_taint should enable depth-limited resolution"
        );
        assert_eq!(after.len(), 1, "should find exactly one taint path");
    }

    #[test]
    fn test_propagate_taint_does_not_exceed_depth() {
        let mut resolver = CrossFileTaintResolver::new();
        // Chain longer than PROPAGATE_MAX_DEPTH
        resolver
            .call_graph
            .insert("a.rs:f0".to_string(), vec!["a.rs:f1".to_string()]);
        resolver
            .call_graph
            .insert("a.rs:f1".to_string(), vec!["a.rs:f2".to_string()]);
        resolver
            .call_graph
            .insert("a.rs:f2".to_string(), vec!["a.rs:f3".to_string()]);
        resolver
            .call_graph
            .insert("a.rs:f3".to_string(), vec!["a.rs:f4".to_string()]);
        resolver
            .call_graph
            .insert("a.rs:f4".to_string(), vec!["a.rs:f5".to_string()]);
        resolver
            .call_graph
            .insert("a.rs:f5".to_string(), vec!["a.rs:f6".to_string()]);
        for i in 1..=6 {
            resolver
                .reverse_call_graph
                .insert(format!("a.rs:f{i}"), vec![format!("a.rs:f{}", i - 1)]);
        }

        resolver.register_exposed_taint("f0", "a.rs", TaintOrigin::UserInput);
        resolver.propagate_taint(None);

        // f1-f5 should be seeded, f6 should not (depth 6 > PROPAGATE_MAX_DEPTH=5)
        for i in 1..=5 {
            assert!(
                resolver.exposed_taint.contains_key(&format!("a.rs:f{i}")),
                "f{i} should be seeded within propagation depth"
            );
        }
        assert!(
            !resolver.exposed_taint.contains_key("a.rs:f6"),
            "f6 beyond PROPAGATE_MAX_DEPTH should not be seeded"
        );
    }

    #[test]
    fn test_resolve_taint_no_sources() {
        let resolver = CrossFileTaintResolver::new();
        let results = resolver.resolve_taint("sink", "test.rs", 3);
        assert!(results.is_empty());
    }

    #[test]
    #[cfg(feature = "full-analysis")]
    fn test_exposed_taint_direct() {
        let mut resolver = CrossFileTaintResolver::new();
        resolver.register_exposed_taint("source", "a.rs", TaintOrigin::UserInput);
        let mut graph = SemanticGraph::new();
        let sym = make_symbol("source", "a.rs");
        graph.add_symbol(sym);
        resolver.build_from_symbols(&[&make_symbol("source", "a.rs")], &graph);
    }
}
