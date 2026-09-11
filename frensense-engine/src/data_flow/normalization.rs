// SPDX-License-Identifier: MIT

use frensense_lang::{LanguageSpec, NodeRole};
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Range {
    pub start_byte: usize,
    pub end_byte: usize,
}

impl From<tree_sitter::Node<'_>> for Range {
    fn from(node: tree_sitter::Node) -> Self {
        Self {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SemanticOp {
    Binding {
        name: String,
        value_range: Range,
    },
    Assignment {
        target: String,
        value_range: Range,
    },
    Call {
        function_name: String,
        args: Vec<Range>,
        range: Range,
    },
    EnterBlock(Range),
}

pub struct SemanticExtractor;

impl SemanticExtractor {
    pub fn extract(node: Node, source: &str, ext: &str) -> Vec<SemanticOp> {
        let spec = frensense_lang::spec_for_ext(ext);
        let mut ops = Vec::new();
        Self::extract_with_spec(node, source, spec, &mut ops);
        ops
    }

    fn extract_bindings(node: Node, source: &str, value_node: Node, ops: &mut Vec<SemanticOp>) {
        match node.kind() {
            "identifier" | "variable_declarator" => {
                let name = source[node.start_byte()..node.end_byte()].to_string();
                ops.push(SemanticOp::Binding {
                    name,
                    value_range: value_node.into(),
                });
            }
            "assignment_pattern" | "shorthand_property_identifier_pattern" => {
                Self::extract_bindings(
                    node.child_by_field_name("key").unwrap_or(node),
                    source,
                    value_node,
                    ops,
                );
            }
            _ => {}
        }
    }

    fn extract_with_spec(
        root: Node,
        source: &str,
        spec: Option<&dyn LanguageSpec>,
        ops: &mut Vec<SemanticOp>,
    ) {
        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            let kind = node.kind();

            let role = spec.map(|s| s.classify(kind)).unwrap_or(NodeRole::Other);

            match role {
                NodeRole::Call {
                    callee_field,
                    args_field,
                } => {
                    let func = node.child_by_field_name(callee_field);
                    let args_node = node.child_by_field_name(args_field);
                    let name = func
                        .map(|f| source[f.start_byte()..f.end_byte()].to_string())
                        .unwrap_or_default();
                    let args = args_node
                        .map(|a| {
                            let mut cursor = a.walk();
                            let mut result = Vec::new();
                            loop {
                                let child = cursor.node();
                                if child.kind() != "comment" {
                                    result.push(Range::from(child));
                                }
                                if !cursor.goto_next_sibling() {
                                    break;
                                }
                            }
                            result
                        })
                        .unwrap_or_default();
                    ops.push(SemanticOp::Call {
                        function_name: name,
                        args,
                        range: node.into(),
                    });
                }
                NodeRole::Declaration {
                    name_field,
                    value_field,
                } => {
                    if let Some(value) = node.child_by_field_name(value_field) {
                        if let Some(pattern) = node.child_by_field_name(name_field) {
                            Self::extract_bindings(pattern, source, value, ops);
                        }
                    }
                }
                NodeRole::Assignment {
                    lhs_field,
                    rhs_field,
                } => {
                    if let (Some(target), Some(value)) = (
                        node.child_by_field_name(lhs_field),
                        node.child_by_field_name(rhs_field),
                    ) {
                        let target_name =
                            source[target.start_byte()..target.end_byte()].to_string();
                        ops.push(SemanticOp::Assignment {
                            target: target_name,
                            value_range: value.into(),
                        });
                    }
                }
                _ => {}
            }

            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }
}
