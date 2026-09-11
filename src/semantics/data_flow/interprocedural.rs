// SPDX-License-Identifier: MIT

//! Interprocedural taint verification.
//!
//! Follows taint flow across function boundaries, callbacks, and promises
//! to verify that user-controlled data actually reaches dangerous sinks.

use std::collections::HashSet;
use tree_sitter::Node;

use crate::semantics::data_flow::TaintOrigin;
use crate::semantics::data_flow::TaintRegistry;
use frensense_engine::corpus::source_sink::{CorpusSourceSinkRegistry, extract_param_info};
use frensense_engine::semantic::SemanticProvider;

/// Result of interprocedural taint verification.
#[derive(Debug, Clone)]
pub struct InterproceduralResult {
    pub verified: bool,
    pub depth: usize,
    pub path: Vec<String>,
    pub detail: String,
}

fn extract_binding_names<'a>(node: Node<'a>, source: &'a str) -> Vec<String> {
    let mut names = Vec::new();
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                names.push(source[n.start_byte()..n.end_byte()].to_string());
            }
            "pair_pattern" => {
                if let Some(value) = n.child_by_field_name("value") {
                    stack.push(value);
                }
            }
            "object_pattern" | "array_pattern" | "struct_pattern" | "tuple_pattern" => {
                let mut cursor = n.walk();
                for child in n.children(&mut cursor) {
                    stack.push(child);
                }
            }
            _ => {}
        }
    }
    names
}

/// Interprocedural taint verifier.
///
/// Follows taint flow through function calls, callbacks, and promises
/// to verify that user-controlled data reaches dangerous sinks.
pub struct InterproceduralVerifier<'a> {
    source: &'a str,
    _tree: &'a tree_sitter::Tree,
    registry: TaintRegistry,
    _visited: HashSet<(String, usize)>,
    max_depth: usize,
    source_sink: &'a CorpusSourceSinkRegistry,
    provider: Option<&'a dyn SemanticProvider>,
    sanitizers: frensense_engine::data_flow::SanitizerRegistry,
    propagators: frensense_engine::data_flow::propagators::PropagatorRegistry,
    cfg: Option<frensense_engine::cfg::ControlFlowGraph<'a>>,
}

impl<'a> InterproceduralVerifier<'a> {
    #[must_use]
    pub fn new(
        source: &'a str,
        tree: &'a tree_sitter::Tree,
        source_sink: &'a CorpusSourceSinkRegistry,
    ) -> Self {
        Self {
            source,
            _tree: tree,
            registry: TaintRegistry::default(),
            _visited: HashSet::new(),
            max_depth: 5,
            source_sink,
            provider: None,
            sanitizers: frensense_engine::data_flow::SanitizerRegistry::default_combined(),
            propagators: frensense_engine::data_flow::propagators::PropagatorRegistry::new(),
            cfg: None,
        }
    }

    /// Create a verifier with a language spec for spec-aware propagator rules.
    #[must_use]
    pub fn with_spec(
        source: &'a str,
        tree: &'a tree_sitter::Tree,
        source_sink: &'a CorpusSourceSinkRegistry,
        spec: &dyn frensense_lang::LanguageSpec,
    ) -> Self {
        Self {
            source,
            _tree: tree,
            registry: TaintRegistry::default(),
            _visited: HashSet::new(),
            max_depth: 5,
            source_sink,
            provider: None,
            sanitizers: frensense_engine::data_flow::SanitizerRegistry::default_combined(),
            propagators: frensense_engine::data_flow::propagators::PropagatorRegistry::from_spec(
                spec,
            ),
            cfg: None,
        }
    }

    #[must_use]
    pub fn with_cfg(mut self, cfg: frensense_engine::cfg::ControlFlowGraph<'a>) -> Self {
        self.cfg = Some(cfg);
        self
    }

    #[must_use]
    pub fn with_provider(mut self, provider: &'a dyn SemanticProvider) -> Self {
        self.provider = Some(provider);
        self
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Seed taint for a function's parameters.
    pub fn seed_taint(&mut self, fn_node: Node, _source_name: &str) {
        self.seed_from_params(fn_node);
        if let Some(body) = fn_node.child_by_field_name("body") {
            crate::semantics::data_flow::corpus_seeder::seed_from_ast_body(
                body,
                self.source,
                &mut self.registry,
            );
        }
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Seed taint from function parameters using corpus-learned source types.
    fn seed_from_params(&mut self, fn_node: Node) {
        let Some(params_node) = fn_node
            .child_by_field_name("parameters")
            .or_else(|| fn_node.child_by_field_name("formal_parameters"))
        else {
            return;
        };

        let mut cursor = params_node.walk();
        for param in params_node.children(&mut cursor) {
            if matches!(param.kind(), "(" | ")" | "," | ";" | "self") {
                continue;
            }

            let (param_name, param_type) = extract_param_info(param, self.source);
            if param_name.is_empty() {
                continue;
            }

            let clean_type = param_type.trim_start_matches(':').trim();
            if let Some(provider) = self.provider {
                if let Some(origin) = provider.classify_param(&param_name, Some(clean_type)) {
                    self.registry.taint(&param_name, origin);
                    return;
                }
            }
            if self.source_sink.is_source_type(clean_type) {
                self.registry.taint(&param_name, TaintOrigin::UserInput);
                return;
            }
        }
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Verify that taint flows from parameters to a sink in the function body.
    pub fn verify_flow(&mut self, fn_node: Node) -> InterproceduralResult {
        let Some(body) = fn_node.child_by_field_name("body") else {
            return InterproceduralResult {
                verified: false,
                depth: 0,
                path: Vec::new(),
                detail: "No function body".to_string(),
            };
        };

        if !self.registry.has_any_tainted() {
            return InterproceduralResult {
                verified: false,
                depth: 0,
                path: Vec::new(),
                detail: "No tainted parameters detected".to_string(),
            };
        }

        // Follow taint through the function body
        self.follow_taint(body, 0, &mut Vec::new())
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Recursively follow taint through a code block.
    fn follow_taint(
        &mut self,
        node: Node,
        depth: usize,
        path: &mut Vec<String>,
    ) -> InterproceduralResult {
        if depth > self.max_depth {
            return InterproceduralResult {
                verified: false,
                depth,
                path: path.clone(),
                detail: "Maximum depth reached".to_string(),
            };
        }

        let kind = node.kind();

        match kind {
            // Check for sink function calls
            "call_expression" => {
                if let Some(result) = self.check_call_for_sink(node, depth, path) {
                    return result;
                }
                // Track taint through callback arguments
                if let Some(result) = self.check_callbacks(node, depth, path) {
                    return result;
                }
                // Track taint through promise chains
                if let Some(result) = self.check_promise_chain(node, depth, path) {
                    return result;
                }
            }
            // Track variable assignments
            "variable_declarator" | "lexical_declaration" => {
                if let Some(name_node) = node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("pattern"))
                    && let Some(value_node) = node.child_by_field_name("value")
                {
                    let names = extract_binding_names(name_node, self.source);
                    // Check if value is tainted
                    if self.is_node_tainted(value_node) {
                        let mut is_sanitized = false;
                        if value_node.kind() == "call_expression" {
                            if let Some(callee) = value_node
                                .child_by_field_name("function")
                                .or_else(|| value_node.child_by_field_name("callee"))
                            {
                                let callee_name =
                                    &self.source[callee.start_byte()..callee.end_byte()];
                                let short_name =
                                    callee_name.rsplit('.').next().unwrap_or(callee_name).trim();
                                if self.sanitizers.is_full_sanitizer(short_name)
                                    || self.sanitizers.is_full_sanitizer(callee_name)
                                {
                                    is_sanitized = true;
                                }
                            }
                        }

                        if !is_sanitized {
                            for name in names {
                                self.registry.taint(&name, TaintOrigin::UserInput);
                            }
                        }
                    } else if self.is_node_environment_source(value_node) {
                        for name in names {
                            self.registry.taint(&name, TaintOrigin::Environment);
                        }
                    }
                }
            }
            // Track assignments
            "assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left")
                    && let Some(right) = node.child_by_field_name("right")
                {
                    let names = extract_binding_names(left, self.source);
                    if self.is_node_tainted(right) {
                        let mut is_sanitized = false;
                        if right.kind() == "call_expression" {
                            if let Some(callee) = right
                                .child_by_field_name("function")
                                .or_else(|| right.child_by_field_name("callee"))
                            {
                                let callee_name =
                                    &self.source[callee.start_byte()..callee.end_byte()];
                                let short_name =
                                    callee_name.rsplit('.').next().unwrap_or(callee_name).trim();
                                if self.sanitizers.is_full_sanitizer(short_name)
                                    || self.sanitizers.is_full_sanitizer(callee_name)
                                {
                                    is_sanitized = true;
                                }
                            }
                        }

                        if is_sanitized {
                            for name in &names {
                                self.registry.untaint(name);
                            }
                        } else {
                            for name in names {
                                self.registry.taint(&name, TaintOrigin::UserInput);
                            }
                        }
                    } else if self.is_node_environment_source(right) {
                        for name in names {
                            self.registry.taint(&name, TaintOrigin::Environment);
                        }
                    } else {
                        // Clear taint on reassignment to a non-tainted value
                        for name in &names {
                            self.registry.untaint(name);
                        }
                    }
                }
            }
            // Track await expressions
            "await_expression" => {
                if let Some(arg) = node.child(0)
                    && self.is_node_tainted(arg)
                {
                    // The awaited value is tainted
                    // Continue tracking in parent context
                }
            }
            _ => {}
        }

        // Recurse into children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                let result = self.follow_taint(child, depth + 1, path);
                if result.verified {
                    return result;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        InterproceduralResult {
            verified: false,
            depth,
            path: path.clone(),
            detail: "No sink found in function body".to_string(),
        }
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Check if a function call is a sink and if tainted data reaches it.
    fn check_call_for_sink(
        &mut self,
        call_node: Node,
        depth: usize,
        path: &mut Vec<String>,
    ) -> Option<InterproceduralResult> {
        let callee = call_node
            .child_by_field_name("function")
            .or_else(|| call_node.child_by_field_name("callee"))
            .or_else(|| call_node.child(0))?;

        let fn_name = &self.source[callee.start_byte()..callee.end_byte()];

        // Check if this is a corpus-learned sink, using the provider when available
        let is_sink = if let Some(provider) = self.provider {
            let resolved_module = provider.resolve_receiver_module(fn_name);
            provider.classify_sink(fn_name, resolved_module.as_deref()).is_some()
        } else {
            self.source_sink.is_sink(fn_name).is_some()
        };
        if !is_sink {
            return None;
        }

        // Check if any argument is tainted
        if let Some(args_list) = call_node.child_by_field_name("arguments") {
            let mut cursor = args_list.walk();
            for arg in args_list.children(&mut cursor) {
                if matches!(arg.kind(), "(" | ")" | ",") {
                    continue;
                }
                if self.is_node_tainted(arg) {
                    if let Some(cfg) = &self.cfg {
                        if let Some(sink_block) =
                            frensense_engine::cfg::block_for_byte(cfg, call_node.start_byte())
                        {
                            if frensense_engine::cfg::has_auth_guard_dominator(
                                cfg,
                                sink_block,
                                self.source,
                            ) {
                                return None;
                            }
                        }
                    }

                    let arg_text = &self.source[arg.start_byte()..arg.end_byte()];
                    path.push(format!("{fn_name}({arg_text})"));
                    return Some(InterproceduralResult {
                        verified: true,
                        depth,
                        path: path.clone(),
                        detail: format!("Tainted data reaches sink '{fn_name}'"),
                    });
                }
            }
        }

        None
    }

    /// Check if tainted data flows through callback arguments.
    ///
    /// Example: `processInput(() => req.query.cmd)`
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// The arrow function receives no arguments, but captures `req` from closure.
    fn check_callbacks(
        &mut self,
        call_node: Node,
        depth: usize,
        path: &mut Vec<String>,
    ) -> Option<InterproceduralResult> {
        let callee = call_node
            .child_by_field_name("function")
            .or_else(|| call_node.child_by_field_name("callee"))
            .or_else(|| call_node.child(0))?;

        let fn_name = &self.source[callee.start_byte()..callee.end_byte()];

        // Check if any argument is a callback (arrow function or function expression)
        if let Some(args_list) = call_node.child_by_field_name("arguments") {
            let mut cursor = args_list.walk();
            for arg in args_list.children(&mut cursor) {
                if matches!(arg.kind(), "(" | ")" | ",") {
                    continue;
                }

                // Check if argument is an arrow function
                if arg.kind() == "arrow_function" {
                    // Follow taint into the arrow function body
                    if let Some(body) = arg.child_by_field_name("body") {
                        let result = self.follow_taint(body, depth + 1, path);
                        if result.verified {
                            return Some(InterproceduralResult {
                                verified: true,
                                depth: result.depth,
                                path: result.path,
                                detail: format!("Tainted data flows through callback to {fn_name}"),
                            });
                        }
                    }
                }

                // Check if argument is a function expression
                if arg.kind() == "function"
                    && let Some(body) = arg.child_by_field_name("body")
                {
                    let result = self.follow_taint(body, depth + 1, path);
                    if result.verified {
                        return Some(InterproceduralResult {
                            verified: true,
                            depth: result.depth,
                            path: result.path,
                            detail: format!("Tainted data flows through callback to {fn_name}"),
                        });
                    }
                }
            }
        }

        None
    }

    /// Check if tainted data flows through a promise chain.
    ///
    /// Example: `getData().then(data => exec(data))`
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// The `.then()` callback receives the resolved value.
    fn check_promise_chain(
        &mut self,
        call_node: Node,
        depth: usize,
        path: &mut Vec<String>,
    ) -> Option<InterproceduralResult> {
        // Check if this is a method call like `.then()` or `.catch()`
        let callee = call_node
            .child_by_field_name("function")
            .or_else(|| call_node.child_by_field_name("callee"))
            .or_else(|| call_node.child(0))?;

        if callee.kind() != "member_expression" {
            return None;
        }

        let method_name = if let Some(prop) = callee.child_by_field_name("property") {
            &self.source[prop.start_byte()..prop.end_byte()]
        } else {
            return None;
        };

        // Check if this is a promise method
        let promise_methods = ["then", "catch", "finally", "tap"];
        if !promise_methods.contains(&method_name) {
            return None;
        }

        // Check if the receiver is tainted (e.g., `getData()` returns tainted data)
        if let Some(object) = callee
            .child_by_field_name("object")
            .or_else(|| callee.child(0))
            && !self.is_node_tainted(object)
        {
            return None;
        }

        // Check if the callback argument receives the resolved value
        if let Some(args_list) = call_node.child_by_field_name("arguments") {
            let mut cursor = args_list.walk();
            for arg in args_list.children(&mut cursor) {
                if matches!(arg.kind(), "(" | ")" | ",") {
                    continue;
                }

                // Check if argument is an arrow function
                if arg.kind() == "arrow_function" {
                    // The first parameter of the callback receives the resolved value
                    // Mark it as tainted
                    if let Some(params) = arg
                        .child_by_field_name("parameters")
                        .or_else(|| arg.child_by_field_name("formal_parameters"))
                    {
                        let mut param_cursor = params.walk();
                        if let Some(first_param) = params
                            .children(&mut param_cursor)
                            .find(|p| !matches!(p.kind(), "(" | ")" | "," | ";"))
                            && let Some(name_node) = first_param
                                .child_by_field_name("name")
                                .or_else(|| first_param.child(0))
                        {
                            let param_name =
                                &self.source[name_node.start_byte()..name_node.end_byte()];
                            self.registry.taint(param_name, TaintOrigin::UserInput);
                        }
                    }

                    // Follow taint into the callback body
                    if let Some(body) = arg.child_by_field_name("body") {
                        let result = self.follow_taint(body, depth + 1, path);
                        if result.verified {
                            return Some(InterproceduralResult {
                                verified: true,
                                depth: result.depth,
                                path: result.path,
                                detail: format!(
                                    "Tainted data flows through .{method_name}() callback"
                                ),
                            });
                        }
                    }
                }

                // Check if argument is a function expression
                if arg.kind() == "function" {
                    if let Some(params) = arg.child_by_field_name("parameters") {
                        let mut param_cursor = params.walk();
                        if let Some(first_param) = params
                            .children(&mut param_cursor)
                            .find(|p| !matches!(p.kind(), "(" | ")" | "," | ";"))
                            && let Some(name_node) = first_param
                                .child_by_field_name("name")
                                .or_else(|| first_param.child(0))
                        {
                            let param_name =
                                &self.source[name_node.start_byte()..name_node.end_byte()];
                            self.registry.taint(param_name, TaintOrigin::UserInput);
                        }
                    }

                    if let Some(body) = arg.child_by_field_name("body") {
                        let result = self.follow_taint(body, depth + 1, path);
                        if result.verified {
                            return Some(InterproceduralResult {
                                verified: true,
                                depth: result.depth,
                                path: result.path,
                                detail: format!(
                                    "Tainted data flows through .{method_name}() callback"
                                ),
                            });
                        }
                    }
                }
            }
        }

        None
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Check if a node is tainted (variable reference or member expression).
    fn is_node_tainted(&self, node: Node) -> bool {
        match node.kind() {
            "identifier" => {
                let name = &self.source[node.start_byte()..node.end_byte()];
                self.registry.is_tainted(name)
            }
            "member_expression" | "field_expression" => {
                // Check if the object is tainted
                if let Some(object) = node.child_by_field_name("object").or_else(|| node.child(0)) {
                    return self.is_node_tainted(object);
                }
                false
            }
            "call_expression" => {
                let callee = node
                    .child_by_field_name("function")
                    .or_else(|| node.child_by_field_name("callee"))
                    .or_else(|| node.child(0));

                if let Some(c) = callee {
                    let fn_name = &self.source[c.start_byte()..c.end_byte()];
                    let mut short_name = fn_name;
                    let mut is_member = false;

                    if matches!(c.kind(), "member_expression" | "field_expression") {
                        is_member = true;
                        if let Some(prop) = c
                            .child_by_field_name("property")
                            .or_else(|| c.child_by_field_name("field"))
                        {
                            short_name = &self.source[prop.start_byte()..prop.end_byte()];
                        }
                    }

                    if let Some(rule) = self
                        .propagators
                        .get_rule(fn_name)
                        .or_else(|| self.propagators.get_rule(short_name))
                    {
                        if rule.tainted_receiver && is_member {
                            if let Some(object) = c.child_by_field_name("object") {
                                if self.is_node_tainted(object) {
                                    return true;
                                }
                            }
                        }

                        if let Some(target_idx) = rule.tainted_arg {
                            if let Some(args_list) = node.child_by_field_name("arguments") {
                                let mut cursor = args_list.walk();
                                let mut arg_idx = 0;
                                for arg in args_list.children(&mut cursor) {
                                    if matches!(arg.kind(), "(" | ")" | ",") {
                                        continue;
                                    }
                                    if arg_idx == target_idx && self.is_node_tainted(arg) {
                                        return true;
                                    }
                                    arg_idx += 1;
                                }
                            }
                        }
                    } else {
                        // Fallback logic for unknown functions
                        if self.is_node_tainted(c) {
                            return true;
                        }

                        if let Some(args_list) = node.child_by_field_name("arguments") {
                            let mut cursor = args_list.walk();
                            for arg in args_list.children(&mut cursor) {
                                if matches!(arg.kind(), "(" | ")" | ",") {
                                    continue;
                                }
                                if self.is_node_tainted(arg) {
                                    return true;
                                }
                            }
                        }
                    }

                    // Return-value taint propagation from known source methods
                    if is_member {
                        if let Some(object) = c.child_by_field_name("object") {
                            if matches!(
                                short_name,
                                "json"
                                    | "text"
                                    | "formData"
                                    | "query"
                                    | "header"
                                    | "param"
                                    | "body"
                                    | "arrayBuffer"
                                    | "first"
                                    | "all"
                                    | "get"
                            ) {
                                if self.is_node_tainted(object) {
                                    return true;
                                }
                            }
                        }
                    }
                }
                false
            }
            // Await expressions preserve taint
            "await_expression" => {
                if let Some(arg) = node.child(0) {
                    return self.is_node_tainted(arg);
                }
                false
            }
            // Template literals with tainted expressions
            "template_string" | "template_literal" => {
                // Check if any expression in the template is tainted
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let child = cursor.node();
                        if child.kind() == "template_substitution"
                            && let Some(expr) = child.child(1)
                        {
                            // Skip the ${ and }
                            if self.is_node_tainted(expr) {
                                return true;
                            }
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                false
            }
            // Bracket notation (JS/TS subscript_expression, Rust index_expression, Python subscript)
            "subscript_expression" | "index_expression" | "subscript" => {
                let object = node
                    .child_by_field_name("object")
                    .or_else(|| node.child_by_field_name("value"))
                    .or_else(|| node.child(0));
                if let Some(obj) = object {
                    return self.is_node_tainted(obj);
                }
                false
            }
            // Binary expressions (concat/arithmetic): tainted if either side is tainted
            "binary_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    if self.is_node_tainted(left) {
                        return true;
                    }
                }
                if let Some(right) = node.child_by_field_name("right") {
                    if self.is_node_tainted(right) {
                        return true;
                    }
                }
                false
            }
            // Parenthesized expressions: recurse on inner
            "parenthesized_expression" => {
                if let Some(inner) = node.child(0) {
                    return self.is_node_tainted(inner);
                }
                false
            }
            _ => false,
        }
    }

    /// Check if a node is an environment variable source.
    fn is_node_environment_source(&self, node: Node) -> bool {
        match node.kind() {
            "member_expression" | "field_expression" => {
                let text = &self.source[node.start_byte()..node.end_byte()];
                text.starts_with("process.env.")
                    || text.starts_with("env.")
                    || text == "process.env"
                    || text == "env"
            }
            "identifier" => {
                let text = &self.source[node.start_byte()..node.end_byte()];
                text == "env" || text == "process.env"
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> CorpusSourceSinkRegistry {
        let mut reg = CorpusSourceSinkRegistry::default();
        reg.source_types.insert("Request".to_string(), 5);
        reg.source_types.insert("Json".to_string(), 3);
        reg.sink_names.insert(
            "exec".to_string(),
            (
                frensense_engine::corpus::source_sink::SinkCategory::CodeExecution,
                4,
            ),
        );
        reg.sink_names.insert(
            "eval".to_string(),
            (
                frensense_engine::corpus::source_sink::SinkCategory::CodeExecution,
                3,
            ),
        );
        reg.sink_names.insert(
            "query".to_string(),
            (
                frensense_engine::corpus::source_sink::SinkCategory::SqlInjection,
                5,
            ),
        );
        reg.sink_names.insert(
            "innerHTML".to_string(),
            (frensense_engine::corpus::source_sink::SinkCategory::Xss, 2),
        );
        reg
    }

    #[test]
    fn test_source_sink_registry() {
        let reg = test_registry();
        assert!(reg.is_source_type("Request"));
        assert!(reg.is_source_type("Json"));
        assert!(!reg.is_source_type("String"));
        assert!(reg.is_sink("exec").is_some());
        assert!(reg.is_sink("eval").is_some());
        assert!(reg.is_sink("Math.random").is_none());
    }

    #[test]
    fn test_verify_flow_simple() {
        let source = "function handler(req: Request) { exec(req.body.cmd); }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let fn_node = tree.root_node().child(0).unwrap();

        let source_sink = test_registry();
        let mut verifier = InterproceduralVerifier::new(source, &tree, &source_sink);
        verifier.seed_taint(fn_node, "req");
        let result = verifier.verify_flow(fn_node);

        assert!(result.verified);
        assert!(result.detail.contains("exec"));
    }

    #[test]
    fn test_verify_flow_callback() {
        let source = r"
function handler(req: Request) {
    const cmd = req.query.cmd;
    exec(cmd);
}
";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let fn_node = tree.root_node().child(0).unwrap();

        let source_sink = test_registry();
        let mut verifier = InterproceduralVerifier::new(source, &tree, &source_sink);
        verifier.seed_taint(fn_node, "req");
        let result = verifier.verify_flow(fn_node);

        assert!(result.verified);
    }

    #[test]
    fn test_verify_flow_no_sink() {
        let source = "function handler(req: Request) { Math.random(req.body.cmd); }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let fn_node = tree.root_node().child(0).unwrap();

        let source_sink = test_registry();
        let mut verifier = InterproceduralVerifier::new(source, &tree, &source_sink);
        verifier.seed_taint(fn_node, "req");
        let result = verifier.verify_flow(fn_node);

        assert!(!result.verified);
    }
}
