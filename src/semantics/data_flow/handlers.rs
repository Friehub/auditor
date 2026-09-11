// SPDX-License-Identifier: MIT

use super::DataFlowAnalyzer;
use super::TaintRegistry;
use crate::Advisory;
use frensense_engine::data_flow::TaintOrigin;
use tree_sitter::Node;

impl<'a> DataFlowAnalyzer<'a, '_> {
    pub(super) fn node_at(
        &self,
        range: crate::semantics::data_flow::normalization::Range,
    ) -> Node<'a> {
        self.current_tree
            .root_node()
            .descendant_for_byte_range(range.start_byte, range.end_byte)
            .unwrap_or_else(|| self.current_tree.root_node())
    }

    fn record_alias_if_assign(&self, target: &str, value_node: Node<'a>) {
        let val_code = &self.current_source[value_node.start_byte()..value_node.end_byte()];
        if val_code == target {
            return;
        }
        let trimmed = val_code.trim();
        if !trimmed.is_empty()
            && !trimmed.contains(' ')
            && !trimmed.contains('(')
            && !trimmed.contains('+')
            && !trimmed.contains('-')
            && !trimmed.contains('*')
            && !trimmed.contains('/')
            && !trimmed.contains('.')
        {
            self.alias_tracker
                .borrow_mut()
                .record_alias(target, trimmed);
        }
    }

    /// Recursively walk an AST node and return the first TaintOrigin found
    /// by checking identifiers and member expressions against the registry.
    ///
    /// This enables taint propagation through:
    ///   - Binary concatenation:  `"SELECT..." + req.body.login`
    ///   - Template literals:     `` `SELECT ${req.body.login}` ``
    ///   - Chained variables:     `var q = taintedVar + suffix`
    ///   - Nested member access:  `req.body.login.trim()`
    ///
    /// String literal fragments and comment nodes are skipped to prevent
    /// false positives from coincidental name matches inside strings.
    fn extract_taint_from_expr(
        &self,
        node: Node<'a>,
        registry: &TaintRegistry,
    ) -> Option<TaintOrigin> {
        let kind = node.kind();

        // Skip literal content — cannot carry taint by reference.
        if matches!(
            kind,
            "string"
                | "string_literal"
                | "string_content"
                | "string_fragment"
                | "raw_string_literal"
                | "raw_string"
                | "quoted_string"
                | "char_literal"
                | "comment"
                | "number"
                | "integer"
                | "float"
                | "boolean"
        ) {
            return None;
        }

        match kind {
            "identifier" => {
                let name = &self.current_source[node.start_byte()..node.end_byte()];
                registry.get_origin(name)
            }
            "member_expression" | "field_expression" => {
                // Check the full expression first (e.g. `req.body`)
                let full = &self.current_source[node.start_byte()..node.end_byte()];
                if let Some(origin) = registry.get_origin(full) {
                    return Some(origin);
                }
                // Walk up the object chain: `req.body.login` → check `req.body` → `req`
                let mut cur = node;
                loop {
                    let obj = cur.child_by_field_name("object").or_else(|| cur.child(0));
                    let Some(obj) = obj else { break };
                    let prefix = &self.current_source[obj.start_byte()..obj.end_byte()];
                    if let Some(origin) = registry.get_origin(prefix) {
                        return Some(origin);
                    }
                    if matches!(obj.kind(), "member_expression" | "field_expression") {
                        cur = obj;
                    } else {
                        break;
                    }
                }
                None
            }
            // For any composite expression, recurse into all children.
            _ => {
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        if let Some(origin) = self.extract_taint_from_expr(cursor.node(), registry)
                        {
                            return Some(origin);
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                None
            }
        }
    }

    pub(super) fn process_binding(
        &self,
        name: &'a str,
        value_range: super::normalization::Range,
        block_range: super::normalization::Range,
        registry: &mut TaintRegistry,
        _advisories: &mut Vec<Advisory>,
    ) {
        if value_range.start_byte >= block_range.start_byte
            && value_range.end_byte <= block_range.end_byte
        {
            let v_node = self.node_at(value_range);
            registry.register_symbol(name, v_node.start_byte(), v_node.end_byte());

            self.record_alias_if_assign(name, v_node);

            // Propagate taint transitively from any tainted sub-expression.
            // This covers binary concatenation, template literals, and chained vars.
            if let Some(origin) = self.extract_taint_from_expr(v_node, registry) {
                registry.taint(name, origin);
            }
        }
    }

    pub(super) fn process_assignment(
        &self,
        target: &'a str,
        value_range: super::normalization::Range,
        block_range: super::normalization::Range,
        registry: &mut TaintRegistry,
        _advisories: &mut Vec<Advisory>,
    ) {
        if value_range.start_byte >= block_range.start_byte
            && value_range.end_byte <= block_range.end_byte
        {
            let v_node = self.node_at(value_range);

            self.record_alias_if_assign(target, v_node);

            // Propagate taint transitively from any tainted sub-expression.
            if let Some(origin) = self.extract_taint_from_expr(v_node, registry) {
                registry.taint(target, origin);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn process_call(
        _function_name: &'a str,
        _args: &[super::normalization::Range],
        _range: super::normalization::Range,
        _block_range: super::normalization::Range,
        _registry: &mut TaintRegistry,
    ) -> Option<Vec<Advisory>> {
        // Call processing retained for potential future corpus-based interprocedural analysis
        None
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn process_enter_block(
        _body_range: super::normalization::Range,
        _block_range: super::normalization::Range,
        _registry: &mut TaintRegistry,
    ) -> Option<Vec<Advisory>> {
        // Block processing retained for potential future corpus-based interprocedural analysis
        None
    }
}
