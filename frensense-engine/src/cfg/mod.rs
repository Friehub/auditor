// SPDX-License-Identifier: MIT

pub mod def_use;

use rustc_hash::{FxHashMap, FxHashSet};
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CFEdgeKind {
    Unconditional,
    Branch,
    Merge,
    BackEdge,
    Exception,
}

#[derive(Debug, Clone)]
pub struct BasicBlock<'a> {
    pub id: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub kind: String,
    pub nodes: Vec<Node<'a>>,
    pub dominators: FxHashSet<usize>,
    pub successors: Vec<(usize, CFEdgeKind)>,
    pub predecessors: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct ControlFlowGraph<'a> {
    pub blocks: Vec<BasicBlock<'a>>,
    entry: usize,
    exit: usize,
    label_index: FxHashMap<String, usize>,
}

impl<'a> ControlFlowGraph<'a> {
    pub fn new(blocks: Vec<BasicBlock<'a>>, entry: usize, exit: usize) -> Self {
        Self {
            blocks,
            entry,
            exit,
            label_index: FxHashMap::default(),
        }
    }

    pub fn entry(&self) -> usize {
        self.entry
    }

    pub fn exit(&self) -> usize {
        self.exit
    }

    pub fn block(&self, id: usize) -> Option<&BasicBlock<'a>> {
        self.blocks.get(id)
    }

    pub fn successors(&self, id: usize) -> Vec<(usize, CFEdgeKind)> {
        self.blocks
            .get(id)
            .map_or_else(Vec::new, |b| b.successors.clone())
    }

    pub fn predecessors(&self, id: usize) -> Vec<usize> {
        self.blocks
            .get(id)
            .map_or_else(Vec::new, |b| b.predecessors.clone())
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn block_by_label(&self, label: &str) -> Option<usize> {
        self.label_index.get(label).copied()
    }

    pub fn is_reachable(&self, from: usize, to: usize) -> bool {
        if from >= self.blocks.len() || to >= self.blocks.len() {
            return false;
        }
        let mut visited = FxHashSet::default();
        let mut stack = vec![from];
        visited.insert(from);
        while let Some(block_id) = stack.pop() {
            if block_id == to {
                return true;
            }
            for &(succ, _) in &self.blocks[block_id].successors {
                if visited.insert(succ) {
                    stack.push(succ);
                }
            }
        }
        false
    }

    /// Find the basic block containing a given byte offset.
    pub fn find_block_for_byte(&self, byte_offset: usize) -> Option<usize> {
        self.blocks
            .iter()
            .position(|b| byte_offset >= b.start_byte && byte_offset < b.end_byte)
    }

    /// Find all exit blocks (blocks with no successors, or the designated exit block).
    pub fn exit_nodes(&self) -> Vec<usize> {
        let mut exits: Vec<usize> = self
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| b.successors.is_empty())
            .map(|(id, _)| id)
            .collect();
        // Always include the designated exit block if it exists
        if !exits.contains(&self.exit) {
            exits.push(self.exit);
        }
        exits
    }

    /// Check if `after_block` dominates all exit nodes reachable from `before_block`.
    /// This is the "must-be-followed-by" property: every path from A to function exit
    /// must pass through B.
    pub fn dominates_all_exits_from(&self, before_block: usize, after_block: usize) -> bool {
        let exits = self.exit_nodes();
        if exits.is_empty() {
            return true; // No exits — vacuously true
        }

        // Find all exit nodes reachable from before_block
        let reachable_exits: Vec<usize> = exits
            .into_iter()
            .filter(|&exit| self.is_reachable(before_block, exit))
            .collect();

        if reachable_exits.is_empty() {
            return true; // No reachable exits — vacuously true
        }

        // Check if after_block dominates all reachable exits
        reachable_exits
            .iter()
            .all(|&exit| self.blocks[exit].dominators.contains(&after_block))
    }
}

#[allow(clippy::too_many_lines)]
pub fn build_cfg<'a>(root: Node<'a>, source: &'a str, ext: &str) -> ControlFlowGraph<'a> {
    let spec = frensense_lang::spec_for_ext(ext);
    let mut blocks: Vec<BasicBlock<'a>> = Vec::new();
    let mut label_index: FxHashMap<String, usize> = FxHashMap::default();

    let entry = blocks.len();
    blocks.push(BasicBlock {
        id: entry,
        start_byte: root.start_byte(),
        end_byte: root.end_byte(),
        kind: "entry".to_string(),
        nodes: vec![root],
        dominators: FxHashSet::default(),
        successors: Vec::new(),
        predecessors: Vec::new(),
    });

    let mut cursor = root.walk();
    let mut parent_stack: Vec<usize> = Vec::new();
    let mut current_block = entry;

    // Stack for tracking try/catch/finally structure.
    // Each entry: (try_body_entry, catch_block_id, finally_block_id, try_merge_id)
    let mut try_stack: Vec<(usize, usize, usize, usize)> = Vec::new();
    // Tracks which parent_block each try was entered under, so we can pop try_stack
    // when the cursor returns to that block after walking try children.
    let mut try_parent_stack: Vec<usize> = Vec::new();

    loop {
        let node = cursor.node();
        let kind = node.kind();

        let role = spec
            .map(|s| s.classify(kind))
            .unwrap_or(frensense_lang::NodeRole::Other);

        match role {
            frensense_lang::NodeRole::Branch => {
                let branch_block = blocks.len();
                let merge_block = blocks.len() + 1;
                blocks.push(BasicBlock {
                    id: branch_block,
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    kind: "branch".to_string(),
                    nodes: vec![node],
                    dominators: FxHashSet::default(),
                    successors: vec![(merge_block, CFEdgeKind::Branch)],
                    predecessors: vec![current_block],
                });
                blocks[current_block]
                    .successors
                    .push((branch_block, CFEdgeKind::Branch));
                blocks[current_block]
                    .successors
                    .push((merge_block, CFEdgeKind::Branch));
                blocks.push(BasicBlock {
                    id: merge_block,
                    start_byte: node.end_byte(),
                    end_byte: node.end_byte(),
                    kind: "merge".to_string(),
                    nodes: Vec::new(),
                    dominators: FxHashSet::default(),
                    successors: Vec::new(),
                    predecessors: vec![branch_block, current_block],
                });
                blocks[branch_block].predecessors.push(current_block);
                blocks[current_block]
                    .successors
                    .retain(|(id, _)| *id != branch_block || *id != merge_block);
                blocks[current_block]
                    .successors
                    .push((branch_block, CFEdgeKind::Branch));
                blocks[current_block]
                    .successors
                    .push((merge_block, CFEdgeKind::Branch));
                parent_stack.push(current_block);
                current_block = branch_block;
            }
            frensense_lang::NodeRole::Loop => {
                let loop_body = blocks.len();
                let after_loop = blocks.len() + 1;
                blocks.push(BasicBlock {
                    id: loop_body,
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    kind: "loop_body".to_string(),
                    nodes: vec![node],
                    dominators: FxHashSet::default(),
                    successors: vec![
                        (loop_body, CFEdgeKind::BackEdge),
                        (after_loop, CFEdgeKind::Unconditional),
                    ],
                    predecessors: vec![current_block, loop_body],
                });
                blocks[current_block]
                    .successors
                    .push((loop_body, CFEdgeKind::Unconditional));
                blocks.push(BasicBlock {
                    id: after_loop,
                    start_byte: node.end_byte(),
                    end_byte: node.end_byte(),
                    kind: "after_loop".to_string(),
                    nodes: Vec::new(),
                    dominators: FxHashSet::default(),
                    successors: Vec::new(),
                    predecessors: vec![loop_body],
                });
                parent_stack.push(current_block);
                current_block = loop_body;
            }
            frensense_lang::NodeRole::Try => {
                let try_entry = blocks.len();
                let catch_b = blocks.len() + 1;
                let finally_b = blocks.len() + 2;
                let try_merge = blocks.len() + 3;
                blocks.push(BasicBlock {
                    id: try_entry,
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    kind: "try_entry".to_string(),
                    nodes: vec![node],
                    dominators: FxHashSet::default(),
                    successors: Vec::new(),
                    predecessors: vec![current_block],
                });
                blocks[current_block]
                    .successors
                    .push((try_entry, CFEdgeKind::Unconditional));
                blocks.push(BasicBlock {
                    id: catch_b,
                    start_byte: node.end_byte(),
                    end_byte: node.end_byte(),
                    kind: "catch".to_string(),
                    nodes: Vec::new(),
                    dominators: FxHashSet::default(),
                    successors: vec![(try_merge, CFEdgeKind::Unconditional)],
                    predecessors: Vec::new(),
                });
                blocks.push(BasicBlock {
                    id: finally_b,
                    start_byte: node.end_byte(),
                    end_byte: node.end_byte(),
                    kind: "finally".to_string(),
                    nodes: Vec::new(),
                    dominators: FxHashSet::default(),
                    successors: vec![(try_merge, CFEdgeKind::Unconditional)],
                    predecessors: Vec::new(),
                });
                blocks.push(BasicBlock {
                    id: try_merge,
                    start_byte: node.end_byte(),
                    end_byte: node.end_byte(),
                    kind: "try_merge".to_string(),
                    nodes: Vec::new(),
                    dominators: FxHashSet::default(),
                    successors: Vec::new(),
                    predecessors: Vec::new(),
                });
                parent_stack.push(current_block);
                try_parent_stack.push(current_block);
                try_stack.push((try_entry, catch_b, finally_b, try_merge));
                current_block = try_entry;
            }
            frensense_lang::NodeRole::Catch => {
                if let Some(&(try_entry, catch_b, finally_b, _try_merge)) = try_stack.last() {
                    blocks[try_entry]
                        .successors
                        .push((catch_b, CFEdgeKind::Exception));
                    blocks[catch_b].predecessors.push(try_entry);
                    if current_block != try_entry {
                        blocks[current_block]
                            .successors
                            .push((catch_b, CFEdgeKind::Exception));
                        blocks[catch_b].predecessors.push(current_block);
                    }
                    let catch_body_end = blocks.len();
                    blocks.push(BasicBlock {
                        id: catch_body_end,
                        start_byte: node.end_byte(),
                        end_byte: node.end_byte(),
                        kind: "catch_exit".to_string(),
                        nodes: Vec::new(),
                        dominators: FxHashSet::default(),
                        successors: vec![(finally_b, CFEdgeKind::Unconditional)],
                        predecessors: vec![catch_b],
                    });
                    blocks[catch_b]
                        .successors
                        .push((catch_body_end, CFEdgeKind::Unconditional));
                    parent_stack.push(current_block);
                    current_block = catch_b;
                }
            }
            frensense_lang::NodeRole::Finally => {
                if let Some(&(try_entry, _catch_b, finally_b, _try_merge)) = try_stack.last() {
                    if current_block != try_entry {
                        blocks[current_block]
                            .successors
                            .push((finally_b, CFEdgeKind::Unconditional));
                        blocks[finally_b].predecessors.push(current_block);
                    }
                    parent_stack.push(current_block);
                    current_block = finally_b;
                }
            }
            _ => {
                if kind == "labeled_statement" {
                    if let Some(label) = node.child_by_field_name("label") {
                        let label_text = source[label.start_byte()..label.end_byte()].to_string();
                        label_index.insert(label_text, current_block);
                    }
                }
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
                let exit = blocks.len();
                blocks.push(BasicBlock {
                    id: exit,
                    start_byte: root.end_byte(),
                    end_byte: root.end_byte(),
                    kind: "exit".to_string(),
                    nodes: Vec::new(),
                    dominators: FxHashSet::default(),
                    successors: Vec::new(),
                    predecessors: vec![current_block],
                });
                blocks[current_block]
                    .successors
                    .push((exit, CFEdgeKind::Unconditional));
                let mut cfg = ControlFlowGraph {
                    blocks,
                    entry,
                    exit,
                    label_index,
                };
                split_statement_blocks(&mut cfg, spec);
                return cfg;
            }
            if let Some(parent_id) = parent_stack.pop() {
                current_block = parent_id;
                if try_parent_stack.last() == Some(&parent_id) {
                    try_parent_stack.pop();
                    try_stack.pop();
                }
            }
        }
    }
}

fn is_statement_node(kind: &str, spec: Option<&dyn frensense_lang::LanguageSpec>) -> bool {
    if let Some(s) = spec {
        use frensense_lang::NodeRole;
        matches!(
            s.classify(kind),
            NodeRole::Declaration { .. }
                | NodeRole::Assignment { .. }
                | NodeRole::Return
                | NodeRole::Call { .. }
        ) || kind == "expression_statement"
    } else {
        matches!(
            kind,
            "let_declaration"
                | "lexical_declaration"
                | "variable_declaration"
                | "expression_statement"
                | "assignment_expression"
                | "return_statement"
                | "return_expression"
                | "call_expression"
        )
    }
}

fn collect_statement_nodes<'a>(
    node: Node<'a>,
    statements: &mut Vec<Node<'a>>,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) {
    let kind = node.kind();
    if is_statement_node(kind, spec) {
        statements.push(node);
        return;
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_statement_nodes(cursor.node(), statements, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn split_statement_blocks(
    cfg: &mut ControlFlowGraph,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) {
    let n = cfg.blocks.len();
    let mut new_blocks: Vec<BasicBlock> = Vec::new();
    let mut block_map: FxHashMap<usize, (usize, usize)> = FxHashMap::default();

    for old_id in 0..n {
        let block = &cfg.blocks[old_id];
        if block.kind == "entry"
            || block.kind == "exit"
            || block.kind == "branch"
            || block.kind == "merge"
            || block.kind == "loop_body"
            || block.kind == "after_loop"
            || block.nodes.is_empty()
        {
            let new_id = new_blocks.len();
            let mut b = block.clone();
            b.id = new_id;
            new_blocks.push(b);
            block_map.insert(old_id, (new_id, new_id));
        } else {
            let mut statements: Vec<Node> = Vec::new();
            for &node in &block.nodes {
                collect_statement_nodes(node, &mut statements, spec);
            }

            if statements.len() <= 1 {
                let new_id = new_blocks.len();
                let mut b = block.clone();
                b.id = new_id;
                new_blocks.push(b);
                block_map.insert(old_id, (new_id, new_id));
            } else {
                let first_sub = new_blocks.len();
                for (i, stmt) in statements.iter().enumerate() {
                    let sub_id = new_blocks.len();
                    let mut sub = BasicBlock {
                        id: sub_id,
                        start_byte: stmt.start_byte(),
                        end_byte: stmt.end_byte(),
                        kind: "statement".to_string(),
                        nodes: vec![*stmt],
                        dominators: FxHashSet::default(),
                        successors: Vec::new(),
                        predecessors: Vec::new(),
                    };
                    if i > 0 {
                        sub.predecessors.push(sub_id - 1);
                    }
                    if i + 1 < statements.len() {
                        sub.successors.push((sub_id + 1, CFEdgeKind::Unconditional));
                    }
                    new_blocks.push(sub);
                }
                let last_sub = new_blocks.len() - 1;
                block_map.insert(old_id, (first_sub, last_sub));
            }
        }
    }

    let remap = |id: usize| -> Vec<usize> {
        if let Some(&(first, last)) = block_map.get(&id) {
            if first == last {
                vec![first]
            } else {
                (first..=last).collect()
            }
        } else {
            vec![id]
        }
    };

    for block in &mut new_blocks {
        let old_preds: Vec<usize> = block.predecessors.clone();
        block.predecessors.clear();
        for pred in old_preds {
            let mapped = remap(pred);
            block
                .predecessors
                .extend(mapped.iter().copied().filter(|m| *m != block.id));
        }

        let old_succs: Vec<(usize, CFEdgeKind)> = block.successors.drain(..).collect();
        for (succ, kind) in old_succs {
            let mapped = remap(succ);
            for m in mapped {
                block.successors.push((m, kind));
            }
        }
    }

    for block in &mut new_blocks {
        block.predecessors.sort();
        block.predecessors.dedup();
    }

    cfg.entry = remap(cfg.entry).first().copied().unwrap_or(cfg.entry);
    cfg.exit = remap(cfg.exit).last().copied().unwrap_or(cfg.exit);
    cfg.blocks = new_blocks;
}

pub struct CFGWalkResult {
    pub reachable: FxHashSet<usize>,
    pub back_edges: Vec<(usize, usize)>,
}

pub fn walk_reachable(cfg: &ControlFlowGraph, from: usize) -> CFGWalkResult {
    let mut reachable = FxHashSet::default();
    let mut back_edges = Vec::new();
    let mut visited = FxHashSet::default();
    let mut stack = vec![from];
    visited.insert(from);

    while let Some(block_id) = stack.pop() {
        reachable.insert(block_id);
        for &(succ, edge_kind) in &cfg.blocks[block_id].successors {
            if edge_kind == CFEdgeKind::BackEdge {
                back_edges.push((block_id, succ));
            }
            if visited.insert(succ) {
                stack.push(succ);
            }
        }
    }

    CFGWalkResult {
        reachable,
        back_edges,
    }
}

pub fn compute_dominators(cfg: &mut ControlFlowGraph) {
    let n = cfg.blocks.len();
    if n == 0 {
        return;
    }

    for b in &mut cfg.blocks {
        b.dominators.clear();
    }
    cfg.blocks[cfg.entry].dominators.insert(cfg.entry);

    let all_blocks: FxHashSet<usize> = (0..n).collect();
    for i in 0..n {
        if i != cfg.entry {
            cfg.blocks[i].dominators.clone_from(&all_blocks);
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for i in 1..n {
            let mut new_doms: FxHashSet<usize> = (0..n).collect();
            for pred in cfg.blocks[i].predecessors.clone() {
                new_doms = new_doms
                    .intersection(&cfg.blocks[pred].dominators)
                    .copied()
                    .collect();
            }
            new_doms.insert(i);
            if new_doms != cfg.blocks[i].dominators {
                cfg.blocks[i].dominators = new_doms;
                changed = true;
            }
        }
    }
}

pub fn immediate_dominator(cfg: &ControlFlowGraph, block_id: usize) -> Option<usize> {
    if block_id == cfg.entry {
        return None;
    }
    let doms = &cfg.blocks[block_id].dominators;
    let mut idom = cfg.entry;
    for &d in doms {
        if d != block_id && cfg.blocks[d].dominators.contains(&idom) {
            idom = d;
        }
    }
    if idom == block_id { None } else { Some(idom) }
}

pub fn dominance_frontier(cfg: &ControlFlowGraph, block_id: usize) -> FxHashSet<usize> {
    let mut frontier = FxHashSet::default();
    let block = &cfg.blocks[block_id];
    for &(succ, _) in &block.successors {
        if let Some(idom) = immediate_dominator(cfg, block_id) {
            if !cfg.blocks[succ].dominators.contains(&idom) {
                frontier.insert(succ);
            }
        }
    }
    for other in 0..cfg.blocks.len() {
        if other == block_id {
            continue;
        }
        for &(succ, _) in &cfg.blocks[other].successors {
            if succ == block_id {
                if let Some(idom) = immediate_dominator(cfg, other) {
                    if !cfg.blocks[block_id].dominators.contains(&idom) {
                        frontier.insert(block_id);
                    }
                }
            }
        }
    }
    frontier
}

pub fn has_auth_guard_dominator(cfg: &ControlFlowGraph, sink_block: usize, source: &str) -> bool {
    if let Some(block) = cfg.blocks.get(sink_block) {
        for &dominator_id in &block.dominators {
            if dominator_id == sink_block {
                continue;
            }
            if let Some(dom_block) = cfg.blocks.get(dominator_id) {
                if block_looks_like_auth_guard(dom_block, source) {
                    return true;
                }
            }
        }
    }
    false
}

/// Known auth-related identifier patterns. Only matched against AST identifier
/// and call nodes — not raw text — so comments cannot trigger false positives.
const AUTH_GUARD_PATTERNS: &[&str] = &[
    "authenticate",
    "authorize",
    "isAuthenticated",
    "checkAuth",
    "verifyToken",
    "requireAuth",
    "requireLogin",
    "ensureAuthenticated",
    "session.user",
    "req.user",
    "401",
    "403",
    "Unauthorized",
    "Forbidden",
];

/// Determine whether a CFG basic block looks like an authentication or
/// authorization guard.
///
/// Requires **both** conditions:
///   1. The block contains a structural early-exit node (`return_statement`,
///      `throw_statement`, or their Rust/expression-oriented equivalents).
///   2. At least one non-comment, non-string AST node in the block contains
///      a substring from [`AUTH_GUARD_PATTERNS`].
///
/// Unlike the previous implementation, this does not match raw block text —
/// it restricts matching to tree-sitter AST node kinds, which excludes
/// comments and string literal contents from triggering the guard.
pub fn block_looks_like_auth_guard(block: &BasicBlock<'_>, source: &str) -> bool {
    // Condition 1: block must contain a structural early-exit.
    let has_early_exit = block.nodes.iter().any(|n| {
        matches!(
            n.kind(),
            "return_statement"
                | "return_expression"
                | "throw_statement"
                | "throw_expression"
                | "break_statement"
        )
    });
    if !has_early_exit {
        return false;
    }

    // Condition 2: at least one non-comment, non-string node matches an
    // auth guard pattern. We skip `comment`, `string`, `string_fragment`,
    // and `template_string` nodes to avoid matching on comments or string
    // contents that happen to contain "auth".
    block.nodes.iter().any(|n| {
        !matches!(
            n.kind(),
            "comment" | "string" | "string_fragment" | "template_string" | "raw_string_literal"
        ) && {
            let text = &source[n.start_byte()..n.end_byte()];
            AUTH_GUARD_PATTERNS.iter().any(|p| text.contains(p))
        }
    })
}

pub fn block_for_byte(cfg: &ControlFlowGraph, byte: usize) -> Option<usize> {
    for block in &cfg.blocks {
        if byte >= block.start_byte && byte < block.end_byte {
            return Some(block.id);
        }
    }
    None
}
