// SPDX-License-Identifier: MIT

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use crate::symbols::Symbol;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    Calls,
    RefersTo,
    OwnedBy,
    Inherits,
    Overrides,
    FlowsFrom,
    SequentiallyFollows,
    InScope,
    Parameter,
    TaintFlow,
}

#[derive(Debug, Clone)]
pub struct TaintFlowRecord {
    pub function_name: String,
    pub file_path: String,
    pub source_pattern: String,
    pub sink_pattern: String,
    pub rule_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    Acquire,
    Release,
    Await,
    Call,
    Assignment,
    Return,
}

#[derive(Debug, Clone)]
pub struct TemporalEvent {
    pub event_type: EventType,
    pub label: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub start_byte: usize,
}

#[derive(Debug, Clone)]
pub enum SemanticNode {
    Declaration(Symbol),
    Event(TemporalEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SemanticNodeId(pub NodeIndex);

#[derive(Debug, Clone, Default)]
pub struct SemanticGraph {
    graph: DiGraph<SemanticNode, EdgeKind>,
    name_index: HashMap<String, Vec<NodeIndex>>,
    taint_flows: Vec<TaintFlowRecord>,
}

impl SemanticGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_symbol(&mut self, symbol: Symbol) -> SemanticNodeId {
        let name = symbol.name.clone();
        let idx = self.graph.add_node(SemanticNode::Declaration(symbol));
        self.name_index.entry(name).or_default().push(idx);
        SemanticNodeId(idx)
    }

    pub fn add_event(&mut self, event: TemporalEvent) -> SemanticNodeId {
        let label = event.label.clone();
        let idx = self.graph.add_node(SemanticNode::Event(event));
        self.name_index.entry(label).or_default().push(idx);
        SemanticNodeId(idx)
    }

    pub fn add_edge(&mut self, from: SemanticNodeId, to: SemanticNodeId, kind: EdgeKind) {
        self.graph.add_edge(from.0, to.0, kind);
    }

    pub fn find_nodes(&self, name: &str) -> Vec<SemanticNodeId> {
        self.name_index
            .get(name)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(SemanticNodeId)
            .collect()
    }

    pub fn get_node(&self, id: SemanticNodeId) -> Option<&SemanticNode> {
        self.graph.node_weight(id.0)
    }

    pub fn get_symbol(&self, id: SemanticNodeId) -> Option<&Symbol> {
        match self.graph.node_weight(id.0) {
            Some(SemanticNode::Declaration(s)) => Some(s),
            _ => None,
        }
    }

    pub fn all_symbols(&self) -> Vec<&Symbol> {
        self.graph
            .node_weights()
            .filter_map(|n| {
                if let SemanticNode::Declaration(s) = n {
                    Some(s)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn find_node(&self, name: &str, file: &str, line: usize) -> Option<SemanticNodeId> {
        self.name_index
            .get(name)
            .and_then(|indices| {
                indices.iter().find(|&&idx| {
                    if let Some(SemanticNode::Declaration(s)) = self.graph.node_weight(idx) {
                        s.file_path == file && (line == 0 || s.line == line)
                    } else {
                        false
                    }
                })
            })
            .copied()
            .map(SemanticNodeId)
    }

    pub fn merge(&mut self, other: SemanticGraph) {
        let mut node_map = HashMap::new();

        // 1. Add all nodes from other graph and map their old indices to new indices
        for idx in other.graph.node_indices() {
            if let Some(weight) = other.graph.node_weight(idx) {
                let new_idx = self.graph.add_node(weight.clone());
                node_map.insert(idx, new_idx);

                // Update name_index
                let name = match weight {
                    SemanticNode::Declaration(s) => s.name.clone(),
                    SemanticNode::Event(e) => e.label.clone(),
                };
                self.name_index.entry(name).or_default().push(new_idx);
            }
        }

        // 2. Add all edges from other graph using the mapped indices
        for edge in other.graph.edge_references() {
            if let (Some(&new_source), Some(&new_target)) =
                (node_map.get(&edge.source()), node_map.get(&edge.target()))
            {
                self.graph.add_edge(new_source, new_target, *edge.weight());
            }
        }

        // 3. Extend taint flows
        self.taint_flows.extend(other.taint_flows);
    }

    pub fn neighbors_of(&self, id: SemanticNodeId, kind: EdgeKind) -> Vec<SemanticNodeId> {
        self.graph
            .edges(id.0)
            .filter(|e| *e.weight() == kind)
            .map(|e| SemanticNodeId(e.target()))
            .collect()
    }

    pub fn incoming_neighbors_of(&self, id: SemanticNodeId, kind: EdgeKind) -> Vec<SemanticNodeId> {
        self.graph
            .edges_directed(id.0, petgraph::Direction::Incoming)
            .filter(|e| *e.weight() == kind)
            .map(|e| SemanticNodeId(e.source()))
            .collect()
    }

    pub fn ordered_events_in_scope(&self, scope_id: SemanticNodeId) -> Vec<TemporalEvent> {
        let mut events = Vec::new();
        let event_ids: Vec<SemanticNodeId> = self
            .neighbors_of(scope_id, EdgeKind::InScope)
            .into_iter()
            .filter(|&id| matches!(self.get_node(id), Some(SemanticNode::Event(_))))
            .collect();

        let event_set: HashSet<NodeIndex> = event_ids.iter().map(|id| id.0).collect();

        let mut starts: Vec<_> = event_set
            .iter()
            .filter(|&&idx| {
                !self
                    .graph
                    .edges_directed(idx, petgraph::Direction::Incoming)
                    .any(|e| {
                        *e.weight() == EdgeKind::SequentiallyFollows
                            && event_set.contains(&e.source())
                    })
            })
            .copied()
            .collect();

        if starts.len() > 1 {
            starts.sort_by(|a, b| {
                let node_a = self.get_node(SemanticNodeId(*a));
                let node_b = self.get_node(SemanticNodeId(*b));
                match (node_a, node_b) {
                    (Some(SemanticNode::Event(ea)), Some(SemanticNode::Event(eb))) => {
                        ea.line.cmp(&eb.line).then(ea.column.cmp(&eb.column))
                    }
                    _ => std::cmp::Ordering::Equal,
                }
            });
        }

        let mut queue: VecDeque<_> = starts.into_iter().collect();
        let mut visited = HashSet::new();
        while let Some(idx) = queue.pop_front() {
            if !visited.insert(idx) {
                continue;
            }
            if let Some(SemanticNode::Event(ev)) = self.get_node(SemanticNodeId(idx)) {
                events.push(ev.clone());
            }
            let mut next_edges: Vec<_> = self
                .graph
                .edges(idx)
                .filter(|e| {
                    *e.weight() == EdgeKind::SequentiallyFollows && event_set.contains(&e.target())
                })
                .collect();
            if next_edges.len() > 1 {
                next_edges.sort_by(|a, b| {
                    let node_a = self.get_node(SemanticNodeId(a.target()));
                    let node_b = self.get_node(SemanticNodeId(b.target()));
                    match (node_a, node_b) {
                        (Some(SemanticNode::Event(ea)), Some(SemanticNode::Event(eb))) => {
                            ea.line.cmp(&eb.line).then(ea.column.cmp(&eb.column))
                        }
                        _ => std::cmp::Ordering::Equal,
                    }
                });
            }
            for e in next_edges {
                queue.push_back(e.target());
            }
        }
        events
    }

    pub fn record_taint_flow(&mut self, record: TaintFlowRecord) {
        let func_name = record.function_name.clone();
        let file_path = record.file_path.clone();
        self.taint_flows.push(record);

        if let Some(node_id) = self.name_index.get(&func_name).and_then(|indices| {
            indices.iter().find(|&&idx| {
                if let Some(SemanticNode::Declaration(s)) = self.graph.node_weight(idx) {
                    s.file_path == file_path
                } else {
                    false
                }
            })
        }) {
            self.graph.add_edge(*node_id, *node_id, EdgeKind::TaintFlow);
        }
    }

    pub fn taint_flows(&self) -> &[TaintFlowRecord] {
        &self.taint_flows
    }

    pub fn has_taint_flow(&self, func_name: &str, file_path: &str) -> bool {
        self.taint_flows
            .iter()
            .any(|r| r.function_name == func_name && r.file_path == file_path)
    }

    pub fn taint_flows_for(&self, func_name: &str, file_path: &str) -> Vec<&TaintFlowRecord> {
        self.taint_flows
            .iter()
            .filter(|r| r.function_name == func_name && r.file_path == file_path)
            .collect()
    }

    pub fn has_call_path(
        &self,
        from_nodes: &[SemanticNodeId],
        to_nodes: &[SemanticNodeId],
    ) -> bool {
        let to_nodes: HashSet<NodeIndex> = to_nodes.iter().map(|id| id.0).collect();
        for from in from_nodes {
            let mut visited = HashSet::new();
            let mut stack = vec![from.0];
            visited.insert(from.0);
            while let Some(current) = stack.pop() {
                if to_nodes.contains(&current) {
                    return true;
                }
                for edge in self.graph.edges(current) {
                    if *edge.weight() == EdgeKind::Calls && visited.insert(edge.target()) {
                        stack.push(edge.target());
                    }
                }
            }
        }
        false
    }
}

pub fn extract_temporal_events<'a>(
    root: tree_sitter::Node<'a>,
    source: &'a str,
    file_path: &Path,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) -> Vec<TemporalEvent> {
    let mut events = Vec::new();
    let mut cursor = root.walk();
    let file_str = file_path.to_string_lossy().to_string();

    loop {
        let node = cursor.node();
        let kind = node.kind();

        let is_call = spec.map_or(kind == "call_expression", |s| {
            matches!(s.classify(kind), frensense_lang::NodeRole::Call { .. })
        });

        if is_call {
            let call_text = node.utf8_text(source.as_bytes()).unwrap_or("");
            let line = node.start_position().row + 1;
            let column = node.start_position().column + 1;

            if call_text.contains(".lock()") || call_text.contains(".lock().") {
                // In Rust, `let guard = mutex.lock()` binds a MutexGuard that is
                // automatically dropped at scope end (RAII). Only flag explicit
                // lock calls that are NOT assigned to a let binding.
                let is_let_binding = {
                    let mut p = node.parent();
                    while let Some(parent) = p {
                        if parent.kind() == "let_declaration"
                            || parent.kind() == "variable_declaration"
                        {
                            break;
                        }
                        // If we hit a function body / block without hitting let_declaration,
                        // this is NOT a let binding.
                        if spec.map_or(
                            matches!(
                                parent.kind(),
                                "function_item"
                                    | "function_definition"
                                    | "arrow_function"
                                    | "method_definition"
                            ),
                            |s| s.is_function_node(parent.kind()),
                        ) {
                            break;
                        }
                        p = parent.parent();
                    }
                    p.is_some_and(|pt| {
                        pt.kind() == "let_declaration" || pt.kind() == "variable_declaration"
                    })
                };

                if !is_let_binding {
                    events.push(TemporalEvent {
                        event_type: EventType::Acquire,
                        label: "lock".to_string(),
                        file_path: file_str.clone(),
                        line,
                        column,
                        start_byte: node.start_byte(),
                    });
                }
            } else if call_text.contains(".await") {
                events.push(TemporalEvent {
                    event_type: EventType::Await,
                    label: "await".to_string(),
                    file_path: file_str.clone(),
                    line,
                    column,
                    start_byte: node.start_byte(),
                });
            } else if call_text.contains(".close()")
                || call_text.contains(".release()")
                || call_text.contains(".drop()")
            {
                events.push(TemporalEvent {
                    event_type: EventType::Release,
                    label: "release".to_string(),
                    file_path: file_str.clone(),
                    line,
                    column,
                    start_byte: node.start_byte(),
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
                return events;
            }
        }
    }
}
