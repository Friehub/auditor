// SPDX-License-Identifier: MIT

use std::path::Path;

use crate::FileId;
#[cfg(feature = "full-analysis")]
use crate::graph::{EdgeKind, SemanticGraph, SemanticNodeId};

#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    Function,
    Struct,
    Class,
    Interface,
    Enum,
    Constant,
    Module,
    Variable,
    Parameter,
    Unknown,
}

#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub start_byte: usize,
    pub end_byte: usize,
    pub file_path: String,
    pub file_id: FileId,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolRegistry {
    #[cfg(feature = "full-analysis")]
    graph: SemanticGraph,
    #[cfg(feature = "full-analysis")]
    file_index: std::collections::HashMap<String, Vec<SemanticNodeId>>,
}

impl SymbolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "full-analysis")]
    pub const fn graph(&self) -> &SemanticGraph {
        &self.graph
    }

    #[cfg(feature = "full-analysis")]
    pub fn insert(&mut self, symbol: Symbol) -> SemanticNodeId {
        let file_path = symbol.file_path.clone();
        let id = self.graph.add_symbol(symbol);
        self.file_index.entry(file_path).or_default().push(id);
        id
    }

    #[cfg(feature = "full-analysis")]
    pub fn merge(&mut self, other: SymbolRegistry) {
        self.graph.merge(other.graph);
        // The node indices in other.file_index are no longer valid because `merge` created new nodes.
        // We actually don't strictly need file_index to be perfectly merged for cross_file taint resolution,
        // as it relies on SemanticGraph, but we should clear or rebuild it if needed.
        // For now, rebuilding file_index is complex without returning the node_map from SemanticGraph::merge.
        // But cross_file.rs relies on `all_symbols()` which uses the SemanticGraph directly.
    }

    #[cfg(feature = "full-analysis")]
    pub fn find(&self, name: &str) -> Vec<&Symbol> {
        self.graph
            .find_nodes(name)
            .into_iter()
            .filter_map(|id| self.graph.get_symbol(id))
            .collect()
    }

    #[cfg(feature = "full-analysis")]
    pub fn find_at(&self, name: &str, file: &str, line: usize) -> Option<&Symbol> {
        self.file_index
            .get(file)?
            .iter()
            .filter_map(|&id| {
                let s = self.graph.get_symbol(id)?;
                if s.name == name && line >= s.line && line <= s.end_line {
                    Some(s)
                } else {
                    None
                }
            })
            .min_by_key(|s| s.end_line - s.line)
    }

    #[cfg(feature = "full-analysis")]
    pub fn find_function_at(&self, file: &str, line: usize) -> Option<SemanticNodeId> {
        self.file_index
            .get(file)?
            .iter()
            .filter(|&&id| {
                self.graph.get_symbol(id).is_some_and(|s| {
                    s.kind == SymbolKind::Function && line >= s.line && line <= s.end_line
                })
            })
            .min_by_key(|&&id| {
                self.graph
                    .get_symbol(id)
                    .map_or(usize::MAX, |s| s.end_line - s.line)
            })
            .copied()
    }

    #[cfg(feature = "full-analysis")]
    pub fn get_symbol(&self, id: SemanticNodeId) -> Option<&Symbol> {
        self.graph.get_symbol(id)
    }

    #[cfg(feature = "full-analysis")]
    pub fn query_all(&self) -> Vec<&Symbol> {
        self.graph.all_symbols()
    }

    #[cfg(feature = "full-analysis")]
    pub fn clear(&mut self) {
        self.graph = SemanticGraph::default();
        self.file_index.clear();
    }

    #[cfg(feature = "full-analysis")]
    pub fn add_call_edge(&mut self, file_path: &Path, src_name: &str, target_name: &str) {
        let file_str = file_path.display().to_string();
        let src_symbols = self.find(src_name);

        let mut t_name = target_name;
        let mut module_hint = None;

        if let Some(idx) = target_name.rfind('.') {
            module_hint = Some(&target_name[..idx]);
            t_name = &target_name[idx + 1..];
        }

        let mut target_symbols = self.find(t_name);
        if target_symbols.is_empty() && module_hint.is_some() {
            target_symbols = self.find(target_name);
        }

        let src_node_id = src_symbols
            .iter()
            .find(|s| s.file_path == file_str)
            .and_then(|s| self.graph.find_node(&s.name, &s.file_path, s.line));

        let mut target_node_id = None;

        if let Some(local) = target_symbols.iter().find(|s| s.file_path == file_str) {
            target_node_id = self
                .graph
                .find_node(&local.name, &local.file_path, local.line);
        } else {
            let mut candidates = target_symbols.clone();
            if let Some(hint) = module_hint {
                let hint_clean = hint.to_lowercase().replace("-", "").replace("_", "");
                candidates.retain(|s| {
                    let path_clean = s.file_path.to_lowercase().replace("-", "").replace("_", "");
                    path_clean.contains(&hint_clean)
                });
            }

            if candidates.len() == 1 {
                target_node_id = self.graph.find_node(
                    &candidates[0].name,
                    &candidates[0].file_path,
                    candidates[0].line,
                );
            } else if target_symbols.len() == 1 {
                target_node_id = self.graph.find_node(
                    &target_symbols[0].name,
                    &target_symbols[0].file_path,
                    target_symbols[0].line,
                );
            }
        }

        if let (Some(s_id), Some(t_id)) = (src_node_id, target_node_id) {
            self.graph.add_edge(s_id, t_id, EdgeKind::Calls);
        }
    }

    #[cfg(feature = "full-analysis")]
    pub fn get_callees(&self, sym: &Symbol) -> Vec<&Symbol> {
        let Some(id) = self.graph.find_node(&sym.name, &sym.file_path, sym.line) else {
            return Vec::new();
        };
        self.graph
            .neighbors_of(id, EdgeKind::Calls)
            .into_iter()
            .filter_map(|i| self.graph.get_symbol(i))
            .collect()
    }

    #[cfg(feature = "full-analysis")]
    pub fn get_callers(&self, sym: &Symbol) -> Vec<&Symbol> {
        let Some(id) = self.graph.find_node(&sym.name, &sym.file_path, sym.line) else {
            return Vec::new();
        };
        self.graph
            .incoming_neighbors_of(id, EdgeKind::Calls)
            .into_iter()
            .filter_map(|i| self.graph.get_symbol(i))
            .collect()
    }

    #[cfg(feature = "full-analysis")]
    pub fn graph_mut(&mut self) -> &mut SemanticGraph {
        &mut self.graph
    }

    #[cfg(feature = "full-analysis")]
    pub fn find_callers(&self, name: &str) -> Vec<&Symbol> {
        let nodes = self.graph.find_nodes(name);
        let mut callers = Vec::new();
        for node in nodes {
            let caller_ids = self.graph.incoming_neighbors_of(node, EdgeKind::Calls);
            for id in caller_ids {
                if let Some(s) = self.graph.get_symbol(id) {
                    callers.push(s);
                }
            }
        }
        callers
    }

    /// Extract symbols from a tree-sitter tree using the given symbol query.
    pub fn extract_from_tree(
        &mut self,
        tree: &tree_sitter::Tree,
        source: &str,
        file_path: &Path,
        file_id: FileId,
        query_str: &str,
    ) {
        use tree_sitter::Query;
        let lang = crate::parser::ParserRegistry::get_language(file_path).ok();
        let Some(lang) = lang else { return };
        let Ok(query) = Query::new(&lang, query_str) else {
            return;
        };
        let mut cursor = tree_sitter::QueryCursor::new();
        let file_str = file_path.to_string_lossy().to_string();

        for m in cursor.matches(&query, tree.root_node(), source.as_bytes()) {
            for capture in m.captures {
                if query.capture_names()[capture.index as usize] == "name" {
                    let node = capture.node;
                    let name = &source[node.start_byte()..node.end_byte()];
                    let symbol = Symbol {
                        name: name.to_string(),
                        kind: SymbolKind::Function,
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        file_path: file_str.clone(),
                        file_id,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        end_line: node.end_position().row + 1,
                    };
                    #[cfg(feature = "full-analysis")]
                    self.insert(symbol);
                }
            }
        }
    }

    /// Extract call edges from a tree-sitter tree using the given call query.
    ///
    /// The query must expose two captures per match:
    ///   `@caller` — the enclosing function / method name
    ///   `@call`   — the callee being invoked
    ///
    /// If a match is missing either capture it is skipped silently.
    pub fn extract_edges_from_tree(
        &mut self,
        tree: &tree_sitter::Tree,
        source: &str,
        file_path: &Path,
        query_str: &str,
    ) {
        use tree_sitter::Query;
        let lang = crate::parser::ParserRegistry::get_language(file_path).ok();
        let Some(lang) = lang else { return };
        let Ok(query) = Query::new(&lang, query_str) else {
            return;
        };

        // Pre-compute capture-name → index map so the hot loop is O(1).
        let capture_names = query.capture_names();
        let caller_idx = capture_names
            .iter()
            .position(|n| *n == "caller")
            .map(|i| i as u32);
        let call_idx = capture_names
            .iter()
            .position(|n| *n == "call")
            .map(|i| i as u32);

        // Both captures must be present in the query; if either is absent the
        // query string is malformed — skip the whole file without panicking.
        let (Some(caller_idx), Some(call_idx)) = (caller_idx, call_idx) else {
            return;
        };

        let mut cursor = tree_sitter::QueryCursor::new();
        for m in cursor.matches(&query, tree.root_node(), source.as_bytes()) {
            // Each match should have exactly one @caller and one @call capture.
            let caller_name = m
                .captures
                .iter()
                .find(|c| c.index == caller_idx)
                .map(|c| &source[c.node.start_byte()..c.node.end_byte()]);
            let callee_name = m
                .captures
                .iter()
                .find(|c| c.index == call_idx)
                .map(|c| &source[c.node.start_byte()..c.node.end_byte()]);

            #[cfg(feature = "full-analysis")]
            if let (Some(caller), Some(callee)) = (caller_name, callee_name) {
                self.add_call_edge(file_path, caller, callee);
            }
        }
    }
}
