// SPDX-License-Identifier: MIT

use crate::cfg::ControlFlowGraph;
use crate::cfg::def_use::DefUseChain;
use rustc_hash::{FxHashMap, FxHashSet};

#[derive(Debug, Clone)]
pub struct PDGNode {
    pub id: usize,
    pub ast_node_id: usize,
    pub block_id: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PDGEdge {
    DataDependence { var_name: String },
    ControlDependence,
}

#[derive(Debug, Clone)]
pub struct ProgramDependenceGraph {
    pub nodes: FxHashMap<usize, PDGNode>,
    pub edges: Vec<(usize, usize, PDGEdge)>,
    pub incoming: FxHashMap<usize, Vec<(usize, PDGEdge)>>,
    pub outgoing: FxHashMap<usize, Vec<(usize, PDGEdge)>>,
}

impl ProgramDependenceGraph {
    pub fn new() -> Self {
        Self {
            nodes: FxHashMap::default(),
            edges: Vec::new(),
            incoming: FxHashMap::default(),
            outgoing: FxHashMap::default(),
        }
    }

    pub fn add_node(&mut self, id: usize, ast_node_id: usize, block_id: usize) {
        self.nodes.insert(
            id,
            PDGNode {
                id,
                ast_node_id,
                block_id,
            },
        );
    }

    pub fn add_edge(&mut self, from: usize, to: usize, kind: PDGEdge) {
        self.edges.push((from, to, kind.clone()));
        self.outgoing
            .entry(from)
            .or_default()
            .push((to, kind.clone()));
        self.incoming.entry(to).or_default().push((from, kind));
    }

    pub fn is_reachable(&self, from: usize, to: usize) -> bool {
        let mut visited = FxHashSet::default();
        let mut stack = vec![from];
        visited.insert(from);

        while let Some(current) = stack.pop() {
            if current == to {
                return true;
            }
            if let Some(outs) = self.outgoing.get(&current) {
                for (next, _) in outs {
                    if visited.insert(*next) {
                        stack.push(*next);
                    }
                }
            }
        }
        false
    }
}

pub fn compute_post_dominators(cfg: &ControlFlowGraph) -> FxHashMap<usize, FxHashSet<usize>> {
    let mut post_doms: FxHashMap<usize, FxHashSet<usize>> = FxHashMap::default();
    let n = cfg.blocks.len();
    if n == 0 {
        return post_doms;
    }

    let all_blocks: FxHashSet<usize> = (0..n).collect();
    for i in 0..n {
        post_doms.insert(i, all_blocks.clone());
    }

    let exits = cfg.exit_nodes();
    for &exit in &exits {
        let mut self_set = FxHashSet::default();
        self_set.insert(exit);
        post_doms.insert(exit, self_set);
    }

    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            if exits.contains(&i) {
                continue;
            }
            let mut new_pdom = all_blocks.clone();
            let mut has_succ = false;
            for &(succ, _) in &cfg.blocks[i].successors {
                has_succ = true;
                if let Some(succ_pdom) = post_doms.get(&succ) {
                    new_pdom = new_pdom.intersection(succ_pdom).cloned().collect();
                }
            }
            if !has_succ {
                new_pdom.clear();
            }
            new_pdom.insert(i);

            if let Some(existing) = post_doms.get(&i) {
                if *existing != new_pdom {
                    post_doms.insert(i, new_pdom);
                    changed = true;
                }
            }
        }
    }
    post_doms
}

pub fn build_pdg(
    cfg: &ControlFlowGraph,
    def_use: &DefUseChain,
    _source: &str,
    _spec: Option<&dyn frensense_lang::spec::LanguageSpec>,
) -> ProgramDependenceGraph {
    let mut pdg = ProgramDependenceGraph::new();

    for def in &def_use.definitions {
        pdg.add_node(def.node, def.node, def.block_id);
    }
    for u in &def_use.uses {
        pdg.add_node(u.node, u.node, u.block_id);
    }

    for (use_idx, def_indices) in &def_use.def_for_use {
        if let Some(use_entry) = def_use.uses.get(*use_idx) {
            for &def_idx in def_indices {
                if let Some(def_entry) = def_use.definitions.get(def_idx) {
                    pdg.add_edge(
                        def_entry.node,
                        use_entry.node,
                        PDGEdge::DataDependence {
                            var_name: use_entry.name.clone(),
                        },
                    );
                }
            }
        }
    }

    // Add Assignment Data Dependence (RHS -> LHS)
    // Using provided spec
    for block in &cfg.blocks {
        for &node in &block.nodes {
            let is_assign = node.kind() == "variable_declarator"
                || node.kind() == "assignment_expression"
                || node.kind() == "lexical_declaration"
                || node.kind() == "let_declaration";
            if is_assign {
                let lhs = node
                    .child_by_field_name("pattern")
                    .or_else(|| node.child_by_field_name("left"))
                    .or_else(|| node.child_by_field_name("name"));
                let rhs = node
                    .child_by_field_name("value")
                    .or_else(|| node.child_by_field_name("right"));

                if let (Some(l), Some(r)) = (lhs, rhs) {
                    let l_start = l.start_byte();
                    let l_end = l.end_byte();
                    let r_start = r.start_byte();
                    let r_end = r.end_byte();

                    // Find defs in LHS
                    let mut lhs_defs = Vec::new();
                    for def in &def_use.definitions {
                        if def.start_byte >= l_start && def.end_byte <= l_end {
                            lhs_defs.push(def.node);
                        }
                    }

                    // Find uses in RHS
                    let mut rhs_uses = Vec::new();
                    for u in &def_use.uses {
                        if u.start_byte >= r_start && u.end_byte <= r_end {
                            rhs_uses.push(u.node);
                        }
                    }

                    // Link RHS Use -> LHS Def
                    for &r_u in &rhs_uses {
                        for &l_d in &lhs_defs {
                            pdg.add_edge(
                                r_u,
                                l_d,
                                PDGEdge::DataDependence {
                                    var_name: "assign".to_string(),
                                },
                            );
                        }
                    }
                }
            }
        }
    }
    pdg
}
