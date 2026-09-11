// SPDX-License-Identifier: MIT

use rustc_hash::{FxHashMap, FxHashSet};
use tree_sitter::Node;

use frensense_lang::NodeRole;
use frensense_lang::spec_for_ext;

use crate::cfg::{BasicBlock, ControlFlowGraph};

#[derive(Debug, Clone)]
pub struct Definition {
    pub name: String,
    pub block_id: usize,
    pub node: usize,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone)]
pub struct Use {
    pub name: String,
    pub block_id: usize,
    pub node: usize,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, Default)]
pub struct DefUseChain {
    pub definitions: Vec<Definition>,
    pub uses: Vec<Use>,
    pub def_for_use: FxHashMap<usize, Vec<usize>>,
    pub use_for_def: FxHashMap<usize, Vec<usize>>,
    pub reaching_defs: FxHashMap<usize, FxHashSet<usize>>,
}

impl DefUseChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn defs_for(&self, name: &str) -> Vec<&Definition> {
        self.definitions.iter().filter(|d| d.name == name).collect()
    }

    pub fn uses_of(&self, name: &str) -> Vec<&Use> {
        self.uses.iter().filter(|u| u.name == name).collect()
    }

    pub fn uses_of_def(&self, def_index: usize) -> Vec<&Use> {
        self.use_for_def
            .get(&def_index)
            .map(|indices| indices.iter().filter_map(|&i| self.uses.get(i)).collect())
            .unwrap_or_default()
    }

    pub fn defs_reaching(&self, use_index: usize) -> Vec<&Definition> {
        self.def_for_use
            .get(&use_index)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&i| self.definitions.get(i))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn find_var_name(node: Node, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "variable_declarator" => {
            let name = &source[node.start_byte()..node.end_byte()];
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        }
        "shorthand_property_identifier_pattern" | "assignment_pattern" => {
            if let Some(key) = node.child_by_field_name("key") {
                find_var_name(key, source)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_uses(
    node: Node,
    source: &str,
    block_id: usize,
    node_counter: &mut usize,
    uses: &mut Vec<Use>,
) {
    match node.kind() {
        "identifier" | "shorthand_property_identifier" => {
            let name = source[node.start_byte()..node.end_byte()].to_string();
            uses.push(Use {
                name,
                block_id,
                node: *node_counter,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
            });
            *node_counter += 1;
        }
        "member_expression" | "field_expression" => {
            let name = source[node.start_byte()..node.end_byte()].to_string();
            uses.push(Use {
                name,
                block_id,
                node: *node_counter,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
            });
            *node_counter += 1;

            if let Some(obj) = node.child_by_field_name("object") {
                extract_uses(obj, source, block_id, node_counter, uses);
            }
        }
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                extract_uses(func, source, block_id, node_counter, uses);
            }
            if let Some(args) = node.child_by_field_name("arguments") {
                for i in 0..args.child_count() {
                    if let Some(arg) = args.child(i) {
                        extract_uses(arg, source, block_id, node_counter, uses);
                    }
                }
            }
        }
        "pair" => {
            if let Some(val) = node.child_by_field_name("value") {
                extract_uses(val, source, block_id, node_counter, uses);
            }
        }
        "property_identifier" => {}
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named() {
                    extract_uses(child, source, block_id, node_counter, uses);
                }
            }
        }
    }
}

fn is_identifier(node: Node) -> bool {
    node.kind() == "identifier"
}

fn extract_ref_names(node: Node, source: &str, names: &mut Vec<String>) {
    match node.kind() {
        "identifier" => {
            names.push(source[node.start_byte()..node.end_byte()].to_string());
        }
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                extract_ref_names(func, source, names);
            }
            if let Some(args) = node.child_by_field_name("arguments") {
                for i in 0..args.child_count() {
                    if let Some(arg) = args.child(i) {
                        extract_ref_names(arg, source, names);
                    }
                }
            }
        }
        "member_expression" | "field_expression" => {
            // Keep the full field path instead of stripping it!
            names.push(source[node.start_byte()..node.end_byte()].to_string());

            // We ALSO want to record a use of the base object, because reading req.body
            // is technically also a read of req. But for exact field-sensitive taint,
            // the full path is the most precise. Let's just use the full path.
            if let Some(obj) = node.child_by_field_name("object") {
                extract_ref_names(obj, source, names);
            }
        }
        "binary_expression" => {
            if let Some(left) = node.child_by_field_name("left") {
                extract_ref_names(left, source, names);
            }
            if let Some(right) = node.child_by_field_name("right") {
                extract_ref_names(right, source, names);
            }
        }
        "unary_expression" => {
            if let Some(arg) = node.child_by_field_name("argument") {
                extract_ref_names(arg, source, names);
            }
        }
        _ => {}
    }
}

fn collect_binding_names_from_pattern(pattern: Node, source: &str, names: &mut Vec<String>) {
    match pattern.kind() {
        "identifier" => {
            names.push(source[pattern.start_byte()..pattern.end_byte()].to_string());
        }
        "object_pattern" => {
            let mut cursor = pattern.walk();
            for child in pattern.children(&mut cursor) {
                match child.kind() {
                    "shorthand_property_identifier_pattern" => {
                        names.push(source[child.start_byte()..child.end_byte()].to_string());
                    }
                    "pair_pattern" => {
                        // { key: bindingName } — take the value (right side)
                        if let Some(val) = child.child_by_field_name("value") {
                            collect_binding_names_from_pattern(val, source, names);
                        }
                    }
                    _ => {}
                }
            }
        }
        "array_pattern" => {
            let mut cursor = pattern.walk();
            for child in pattern.children(&mut cursor) {
                if !matches!(child.kind(), "[" | "]" | ",") {
                    collect_binding_names_from_pattern(child, source, names);
                }
            }
        }
        _ => {}
    }
}

fn scan_statement_def_uses(
    node: Node,
    block_id: usize,
    source: &str,
    definitions: &mut Vec<Definition>,
    uses: &mut Vec<Use>,
    node_counter: &mut usize,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) {
    let kind = node.kind();

    let matched = spec.map(|s| s.classify(kind));

    match matched {
        Some(NodeRole::Function {
            is_method: _,
            name_field: _,
            params_field,
            body_field: _,
        }) => {
            if let Some(params) = node.child_by_field_name(params_field) {
                let mut cursor = params.walk();
                for child in params.children(&mut cursor) {
                    if child.is_named() && !matches!(child.kind(), "," | "(" | ")" | "[" | "]") {
                        let mut names = Vec::new();
                        collect_binding_names_from_pattern(child, source, &mut names);
                        for name in names {
                            definitions.push(Definition {
                                name,
                                block_id,
                                node: *node_counter,
                                start_byte: child.start_byte(),
                                end_byte: child.end_byte(),
                            });
                            *node_counter += 1;
                        }
                    }
                }
            }
        }
        Some(NodeRole::Declaration { .. }) => {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                let mut names = Vec::new();
                collect_binding_names_from_pattern(pattern, source, &mut names);
                for name in names {
                    definitions.push(Definition {
                        name,
                        block_id,
                        node: *node_counter,
                        start_byte: pattern.start_byte(),
                        end_byte: pattern.end_byte(),
                    });
                    *node_counter += 1;
                }
            } else if let Some(left) = node.child_by_field_name("left") {
                if let Some(name) = find_var_name(left, source) {
                    definitions.push(Definition {
                        name,
                        block_id,
                        node: *node_counter,
                        start_byte: left.start_byte(),
                        end_byte: left.end_byte(),
                    });
                    *node_counter += 1;
                }
            } else if let Some(name_node) = node.child_by_field_name("name") {
                if let Some(name) = find_var_name(name_node, source) {
                    definitions.push(Definition {
                        name,
                        block_id,
                        node: *node_counter,
                        start_byte: name_node.start_byte(),
                        end_byte: name_node.end_byte(),
                    });
                    *node_counter += 1;
                }
            }
            if let Some(value) = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("right"))
            {
                let mut refs = Vec::new();
                extract_ref_names(value, source, &mut refs);
                for r in refs {
                    uses.push(Use {
                        name: r,
                        block_id,
                        node: *node_counter,
                        start_byte: value.start_byte(),
                        end_byte: value.end_byte(),
                    });
                    *node_counter += 1;
                }
            }
        }
        Some(NodeRole::Assignment { .. }) => {
            if let Some(left) = node.child_by_field_name("left") {
                if let Some(name) = find_var_name(left, source) {
                    definitions.push(Definition {
                        name,
                        block_id,
                        node: *node_counter,
                        start_byte: left.start_byte(),
                        end_byte: left.end_byte(),
                    });
                    *node_counter += 1;
                }
            }
            if let Some(right) = node.child_by_field_name("right") {
                let mut refs = Vec::new();
                extract_ref_names(right, source, &mut refs);
                for r in refs {
                    uses.push(Use {
                        name: r,
                        block_id,
                        node: *node_counter,
                        start_byte: right.start_byte(),
                        end_byte: right.end_byte(),
                    });
                    *node_counter += 1;
                }
            }
        }
        Some(NodeRole::Call { .. }) => {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = source[func.start_byte()..func.end_byte()].to_string();
                uses.push(Use {
                    name: func_name,
                    block_id,
                    node: *node_counter,
                    start_byte: func.start_byte(),
                    end_byte: func.end_byte(),
                });
                *node_counter += 1;
            }
            if let Some(args) = node.child_by_field_name("arguments") {
                for i in 0..args.child_count() {
                    if let Some(arg) = args.child(i) {
                        extract_uses(arg, source, block_id, node_counter, uses);
                    }
                }
            }
        }
        Some(NodeRole::Return) => {
            if let Some(value) = node.child_by_field_name("value") {
                let mut refs = Vec::new();
                extract_ref_names(value, source, &mut refs);
                for r in refs {
                    uses.push(Use {
                        name: r,
                        block_id,
                        node: *node_counter,
                        start_byte: value.start_byte(),
                        end_byte: value.end_byte(),
                    });
                    *node_counter += 1;
                }
            }
        }
        _ => {
            // Fallback: raw kind matching when spec is None or kind doesn't classify
            match kind {
                "let_declaration" | "lexical_declaration" | "variable_declaration" => {
                    if let Some(pattern) = node.child_by_field_name("pattern") {
                        let mut names = Vec::new();
                        collect_binding_names_from_pattern(pattern, source, &mut names);
                        for name in names {
                            definitions.push(Definition {
                                name,
                                block_id,
                                node: *node_counter,
                                start_byte: pattern.start_byte(),
                                end_byte: pattern.end_byte(),
                            });
                            *node_counter += 1;
                        }
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        extract_uses(value, source, block_id, node_counter, uses);
                    }
                }
                "assignment_expression" | "assignment" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        if let Some(name) = find_var_name(left, source) {
                            definitions.push(Definition {
                                name,
                                block_id,
                                node: *node_counter,
                                start_byte: left.start_byte(),
                                end_byte: left.end_byte(),
                            });
                            *node_counter += 1;
                        }
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        extract_uses(right, source, block_id, node_counter, uses);
                    }
                }
                "call_expression" => {
                    if let Some(func) = node.child_by_field_name("function") {
                        let func_name = source[func.start_byte()..func.end_byte()].to_string();
                        uses.push(Use {
                            name: func_name,
                            block_id,
                            node: *node_counter,
                            start_byte: func.start_byte(),
                            end_byte: func.end_byte(),
                        });
                        *node_counter += 1;
                    }
                    if let Some(args) = node.child_by_field_name("arguments") {
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                extract_uses(arg, source, block_id, node_counter, uses);
                            }
                        }
                    }
                }
                "return_statement" | "return_expression" => {
                    if let Some(value) = node.child_by_field_name("value") {
                        extract_uses(value, source, block_id, node_counter, uses);
                    }
                }
                _ => {}
            }
        }
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            scan_statement_def_uses(
                cursor.node(),
                block_id,
                source,
                definitions,
                uses,
                node_counter,
                spec,
            );
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}
fn collect_statements<'a>(node: Node<'a>, statements: &mut Vec<Node<'a>>) {
    let kind = node.kind();
    if kind == "block" || kind == "block_expression" || kind == "statement_block" {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                let ck = child.kind();
                if ck != "{" && ck != "}" {
                    statements.push(child);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        return;
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_statements(cursor.node(), statements);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn scan_block_def_uses<'a>(
    block: &BasicBlock<'a>,
    source: &'a str,
    definitions: &mut Vec<Definition>,
    uses: &mut Vec<Use>,
    node_counter: &mut usize,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) {
    let mut statements = Vec::new();
    for &node in &block.nodes {
        collect_statements(node, &mut statements);
    }
    for stmt in &statements {
        scan_statement_def_uses(
            *stmt,
            block.id,
            source,
            definitions,
            uses,
            node_counter,
            spec,
        );
    }
}

fn compute_reaching_defs(cfg: &ControlFlowGraph, chains: &mut DefUseChain) {
    let n = cfg.blocks.len();
    for i in 0..n {
        chains.reaching_defs.entry(i).or_default();
    }

    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            let mut incoming: FxHashSet<usize> = FxHashSet::default();
            for &pred in &cfg.blocks[i].predecessors {
                if let Some(rd) = chains.reaching_defs.get(&pred) {
                    incoming.extend(rd);
                }
            }

            let block_defs: FxHashSet<usize> = chains
                .definitions
                .iter()
                .enumerate()
                .filter(|(_, d)| d.block_id == i)
                .map(|(idx, _)| idx)
                .collect();

            let def_names: FxHashSet<&str> = block_defs
                .iter()
                .filter_map(|&idx| chains.definitions.get(idx))
                .map(|d| d.name.as_str())
                .collect();

            let mut new_rd: FxHashSet<usize> = incoming
                .into_iter()
                .filter(|&idx| {
                    chains
                        .definitions
                        .get(idx)
                        .is_none_or(|d| !def_names.contains(d.name.as_str()))
                })
                .collect();
            new_rd.extend(&block_defs);

            if let Some(existing) = chains.reaching_defs.get(&i) {
                if *existing != new_rd {
                    chains.reaching_defs.insert(i, new_rd);
                    changed = true;
                }
            } else {
                chains.reaching_defs.insert(i, new_rd);
                changed = true;
            }
        }
    }
}

pub fn compute_def_use<'a>(
    cfg: &ControlFlowGraph<'a>,
    source: &'a str,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) -> DefUseChain {
    let mut chains = DefUseChain::new();
    let mut node_counter = 0usize;

    for block in &cfg.blocks {
        scan_block_def_uses(
            block,
            source,
            &mut chains.definitions,
            &mut chains.uses,
            &mut node_counter,
            spec,
        );
    }

    compute_reaching_defs(cfg, &mut chains);

    for (use_idx, use_) in chains.uses.iter().enumerate() {
        let mut reaching_defs: Vec<usize> = Vec::new();
        if let Some(rd) = chains.reaching_defs.get(&use_.block_id) {
            for &def_idx in rd {
                if let Some(def) = chains.definitions.get(def_idx) {
                    if def.name == use_.name {
                        reaching_defs.push(def_idx);
                        chains.use_for_def.entry(def_idx).or_default().push(use_idx);
                    }
                }
            }
        }
        chains.def_for_use.insert(use_idx, reaching_defs);
    }

    chains
}

pub fn build_def_use<'a>(root: Node<'a>, source: &'a str, ext: &str) -> DefUseChain {
    let spec = spec_for_ext(ext);
    let cfg = crate::cfg::build_cfg(root, source, ext);
    compute_def_use(&cfg, source, spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_def_use_simple_let() {
        let source = "fn foo() { let x = 1; let y = x + 1; }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let chain = build_def_use(root, source, "rs");
        assert!(!chain.definitions.is_empty(), "should have definitions");
        assert!(!chain.uses.is_empty(), "should have uses");
    }

    #[test]
    fn test_no_duplicate_uses() {
        let source = r"
fn no_dup() {
    let x = get_password();
    store_in_db(x);
}
";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let chain = build_def_use(root, source, "rs");

        let get_password_uses: usize = chain
            .uses
            .iter()
            .filter(|u| u.name == "get_password")
            .count();
        assert!(
            get_password_uses <= 2,
            "should not have massive duplication of get_password uses, got {get_password_uses}"
        );
    }

    #[test]
    fn test_def_use_for_reassign() {
        let source = r#"
fn reassign() {
    let x = get_password();
    x = "safe";
    store_in_db(x);
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let chain = build_def_use(root, source, "rs");

        let x_defs: Vec<_> = chain.definitions.iter().filter(|d| d.name == "x").collect();
        assert_eq!(x_defs.len(), 2, "should have two definitions of x");
        assert!(
            chain.uses.iter().any(|u| u.name == "x"),
            "should have use of x"
        );
    }
}

#[test]
fn test_variable_declaration_js() {
    let source = "var query = req.body.login + '1';";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    println!("{}", tree.root_node().to_sexp());
}
