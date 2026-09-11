// SPDX-License-Identifier: MIT

//! Cross-file taint verification.
//!
//! Follows taint flow across file boundaries to verify that
//! user-controlled data reaches dangerous sinks through imports and exports.

use rustc_hash::FxHashMap;
use std::collections::HashSet;
use tree_sitter::Node;

use crate::semantics::data_flow::TaintOrigin;
use crate::semantics::data_flow::TaintRegistry;
use crate::semantics::symbols::SymbolRegistry;
use frensense_engine::corpus::source_sink::{CorpusSourceSinkRegistry, extract_param_info};
use frensense_engine::data_flow::DataFlowEngine;
use frensense_engine::data_flow::DefState;
use frensense_engine::data_flow::resolver::{SymbolEntry, resolve_fn_definition};
use frensense_engine::semantic::SemanticProvider;

/// Result of cross-file taint verification.
#[derive(Debug, Clone)]
pub struct CrossFileResult {
    pub verified: bool,
    pub depth: usize,
    pub path: Vec<String>,
    pub detail: String,
    pub source_name: Option<String>,
    pub sink_name: Option<String>,
    /// Line number (0-indexed) of the actual sink node, if known.
    pub sink_line: Option<u32>,
}

fn extract_binding_names<'a>(node: Node<'a>, source: &'a str) -> Vec<String> {
    let mut names = Vec::new();
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                names.push(source[n.start_byte()..n.end_byte()].to_string());
            }
            "member_expression" | "field_expression" => {
                // For `this.db` or `self.x`, use the full text as the name
                // so that `is_node_tainted` can match it later.
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

/// Cross-file taint verifier.
///
/// Follows taint flow through imports/exports and function calls
/// across multiple files to verify that user-controlled data
/// reaches dangerous sinks.
pub struct CrossFileVerifier<'a> {
    source: &'a str,
    tree: &'a tree_sitter::Tree,
    file_path: String,
    file_env: Option<frensense_engine::context::Environment>,
    registry: TaintRegistry,
    /// Reaching-definitions state for AST-structural taint tracking.
    /// Instead of checking "is this name tainted?", we track
    /// "which definitions reach this point and are they tainted?"
    defs: frensense_engine::data_flow::DefState,
    _symbols: &'a SymbolRegistry,
    data_flow: &'a DataFlowEngine,
    file_trees: &'a rustc_hash::FxHashMap<
        String,
        (
            tree_sitter::Tree,
            String,
            Vec<crate::semantics::data_flow::normalization::SemanticOp>,
        ),
    >,
    _visited: HashSet<(String, usize)>,
    max_depth: usize,
    source_sink: &'a CorpusSourceSinkRegistry,
    deps: &'a std::collections::HashSet<String>,
    provider: Option<&'a dyn SemanticProvider>,
    pub source_name: Option<String>,
    pub potential_sink_name: Option<String>,
    pub sanitizers: frensense_engine::data_flow::SanitizerRegistry,
    pub propagators: frensense_engine::data_flow::propagators::PropagatorRegistry,
    cfg: Option<frensense_engine::cfg::ControlFlowGraph<'a>>,
}

impl<'a> CrossFileVerifier<'a> {
    #[must_use]
    pub fn new(
        source: &'a str,
        tree: &'a tree_sitter::Tree,
        file_path: &str,
        symbols: &'a SymbolRegistry,
        data_flow: &'a DataFlowEngine,
        file_trees: &'a rustc_hash::FxHashMap<
            String,
            (
                tree_sitter::Tree,
                String,
                Vec<crate::semantics::data_flow::normalization::SemanticOp>,
            ),
        >,
        source_sink: &'a CorpusSourceSinkRegistry,
        deps: &'a std::collections::HashSet<String>,
    ) -> Self {
        Self {
            source,
            tree,
            file_path: file_path.to_string(),
            file_env: None,
            registry: TaintRegistry::default(),
            defs: frensense_engine::data_flow::DefState::new(),
            _symbols: symbols,
            data_flow,
            file_trees,
            _visited: HashSet::new(),
            max_depth: 10,
            source_sink,
            deps,
            provider: None,
            source_name: None,
            potential_sink_name: None,
            sanitizers: frensense_engine::data_flow::SanitizerRegistry::default_combined(),
            propagators: frensense_engine::data_flow::propagators::PropagatorRegistry::new(),
            cfg: None,
        }
    }

    /// Expose the taint registry so callers can read taint state without borrowing self mutably.
    #[must_use]
    pub fn registry(&self) -> &TaintRegistry {
        &self.registry
    }

    #[must_use]
    pub fn with_cfg(mut self, cfg: frensense_engine::cfg::ControlFlowGraph<'a>) -> Self {
        self.cfg = Some(cfg);
        self
    }

    #[must_use]
    pub fn with_file_env(mut self, env: frensense_engine::context::Environment) -> Self {
        self.file_env = Some(env);
        self
    }

    #[must_use]
    pub fn with_provider(mut self, provider: &'a dyn SemanticProvider) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Seed taint for a function's parameters.
    ///
    /// Uses corpus-learned source types: taints parameters whose type annotations
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// match types found in positive corpus examples.
    pub fn seed_taint(&mut self, fn_node: Node) {
        self.seed_taint_recursive(fn_node);
        if let Some(body) = fn_node.child_by_field_name("body") {
            crate::semantics::data_flow::corpus_seeder::seed_from_ast_body(
                body,
                self.source,
                &mut self.registry,
            );
        }
    }

    fn seed_taint_recursive(&mut self, node: Node) {
        // Seed parameters of this node if it's a function
        if let Some(params_node) = node
            .child_by_field_name("parameters")
            .or_else(|| node.child_by_field_name("formal_parameters"))
        {
            let mut cursor = params_node.walk();
            for param in params_node.children(&mut cursor) {
                if matches!(param.kind(), "(" | ")" | "," | ";" | "self") {
                    continue;
                }

                let (mut param_name, param_type) = extract_param_info(param, self.source);
                if param_name.is_empty() && param.kind() == "identifier" {
                    param_name = self.source[param.start_byte()..param.end_byte()].to_string();
                }
                if param_name.is_empty() {
                    continue;
                }

                let clean_type = param_type.trim_start_matches(':').trim();

                // Prefer the type-checked provider when one is attached; fall
                // back to the corpus-learned type / name heuristic otherwise.
                let origin = if let Some(provider) = self.provider {
                    provider
                        .classify_param(&param_name, Some(clean_type))
                        .or_else(|| {
                            frensense_engine::data_flow::classify_param_name_in_context(
                                &param_name,
                                self.file_env.as_ref(),
                            )
                        })
                } else if self.source_sink.is_source_type(clean_type) {
                    Some(TaintOrigin::UserInput)
                } else {
                    frensense_engine::data_flow::classify_param_name_in_context(
                        &param_name,
                        self.file_env.as_ref(),
                    )
                };

                if let Some(origin) = origin {
                    self.registry.taint(&param_name, origin.clone());
                    self.defs.taint(&param_name, origin);
                    if self.source_name.is_none() {
                        self.source_name = Some(param_name);
                    }
                }
            }
        }

        // Recurse into children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.seed_taint_recursive(cursor.node());
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Verify that taint flows from parameters to a sink across files.
    pub fn verify_flow(&mut self, fn_node: Node) -> CrossFileResult {
        let Some(body) = fn_node.child_by_field_name("body") else {
            return CrossFileResult {
                verified: false,
                depth: 0,
                path: Vec::new(),
                detail: "No function body".to_string(),
                source_name: None,
                sink_name: None,
                sink_line: None,
            };
        };

        // Check if any parameter is tainted (AST-seeded, not name-based)
        if !self.registry.has_any_tainted() {
            return CrossFileResult {
                verified: false,
                depth: 0,
                path: Vec::new(),
                detail: "No tainted parameters detected".to_string(),
                source_name: None,
                sink_name: None,
                sink_line: None,
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
    ) -> CrossFileResult {
        if depth > self.max_depth {
            return CrossFileResult {
                verified: false,
                depth,
                path: path.clone(),
                detail: "Maximum depth reached".to_string(),
                source_name: None,
                sink_name: None,
                sink_line: None,
            };
        }

        let kind = node.kind();

        match kind {
            // Check for sink function calls
            "call_expression" => {
                if let Some(result) = self.check_call_for_sink(node, depth, path) {
                    return result;
                }
                // Check if tainted data flows through callback arguments
                if let Some(result) = self.check_callbacks(node, depth, path) {
                    return result;
                }
                // Check if tainted data flows through promise chains
                if let Some(result) = self.check_promise_chain(node, depth, path) {
                    return result;
                }
            }
            // Check for object properties with sink names (e.g., $where in MongoDB)
            "object" => {
                if let Some(result) = self.check_object_for_sink(node, depth, path) {
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
                            let value_text =
                                &self.source[value_node.start_byte()..value_node.end_byte()];
                            if !self.source_sink.is_sanitizer_call(value_text) {
                                for name in &names {
                                    self.registry.taint(name, TaintOrigin::UserInput);
                                    self.defs.taint(name, TaintOrigin::UserInput);
                                }
                            }
                        }
                    } else if self.is_node_environment_source(value_node) {
                        for name in names {
                            self.registry.taint(&name, TaintOrigin::Environment);
                            self.defs.taint(&name, TaintOrigin::Environment);
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
                                self.defs.untaint(name);
                            }
                        } else {
                            let value_text = &self.source[right.start_byte()..right.end_byte()];
                            if !self.source_sink.is_sanitizer_call(value_text) {
                                for name in &names {
                                    self.registry.taint(&name, TaintOrigin::UserInput);
                                    self.defs.taint(name, TaintOrigin::UserInput);
                                }
                            }
                        }
                    } else if self.is_node_environment_source(right) {
                        for name in names {
                            self.registry.taint(&name, TaintOrigin::Environment);
                            self.defs.taint(&name, TaintOrigin::Environment);
                        }
                    } else {
                        // Clear taint on reassignment to a non-tainted value
                        for name in &names {
                            self.registry.untaint(name);
                            self.defs.untaint(name);
                        }
                    }
                }
            }
            // Handle if/else with fork/merge to avoid cross-branch taint leakage
            "if_statement" => {
                // Process condition first (it sees current state)
                if let Some(condition) = node.child_by_field_name("condition") {
                    let cond_result = self.follow_taint(condition, depth + 1, path);
                    if cond_result.verified {
                        return cond_result;
                    }
                }

                // Fork state for consequence (then branch)
                let state_before = self.defs.fork();
                if let Some(consequence) = node.child_by_field_name("consequence") {
                    let then_result = self.follow_taint(consequence, depth + 1, path);
                    if then_result.verified {
                        return then_result;
                    }
                }
                let state_then = self.defs.clone();

                // Fork from original state for alternate (else branch)
                self.defs = state_before;
                if let Some(alternate) = node.child_by_field_name("alternate") {
                    let else_result = self.follow_taint(alternate, depth + 1, path);
                    if else_result.verified {
                        return else_result;
                    }
                }
                let state_else = self.defs.clone();

                // Merge: a variable is tainted after merge only if it's tainted
                // in at least one branch (union merge for soundness)
                self.defs = state_then;
                self.defs.merge_union(&state_else);

                return CrossFileResult {
                    verified: false,
                    depth,
                    path: path.clone(),
                    detail: "No sink found in if/else".to_string(),
                    source_name: self.source_name.clone(),
                    sink_name: self.potential_sink_name.clone(),
                    sink_line: None,
                };
            }
            // Handle switch statements with fork/merge per case
            "switch_statement" => {
                if let Some(discriminant) = node.child_by_field_name("value") {
                    let disc_result = self.follow_taint(discriminant, depth + 1, path);
                    if disc_result.verified {
                        return disc_result;
                    }
                }

                let state_before = self.defs.fork();
                let mut case_states: Vec<DefState> = Vec::new();

                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let child = cursor.node();
                        if child.kind() == "switch_case" {
                            self.defs = state_before.clone();
                            // Process case body statements
                            let mut body_cursor = child.walk();
                            if body_cursor.goto_first_child() {
                                loop {
                                    let body_child = body_cursor.node();
                                    let result = self.follow_taint(body_child, depth + 1, path);
                                    if result.verified {
                                        return result;
                                    }
                                    if !body_cursor.goto_next_sibling() {
                                        break;
                                    }
                                }
                            }
                            case_states.push(self.defs.clone());
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }

                // Merge all case states
                if !case_states.is_empty() {
                    self.defs = case_states[0].clone();
                    for state in &case_states[1..] {
                        self.defs.merge_union(state);
                    }
                }

                return CrossFileResult {
                    verified: false,
                    depth,
                    path: path.clone(),
                    detail: "No sink found in switch".to_string(),
                    source_name: self.source_name.clone(),
                    sink_name: self.potential_sink_name.clone(),
                    sink_line: None,
                };
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

        CrossFileResult {
            verified: false,
            depth,
            path: path.clone(),
            detail: "No sink found in function body".to_string(),
            source_name: self.source_name.clone(),
            sink_name: self.potential_sink_name.clone(),
            sink_line: None,
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
    ) -> Option<CrossFileResult> {
        let callee = call_node
            .child_by_field_name("function")
            .or_else(|| call_node.child_by_field_name("callee"))
            .or_else(|| call_node.child(0))?;

        let fn_name_full = &self.source[callee.start_byte()..callee.end_byte()];

        // Apply safe-base filtering to avoid false positives on native objects
        if fn_name_full.starts_with("Object.")
            || fn_name_full.starts_with("Array.")
            || fn_name_full.starts_with("String.")
            || fn_name_full.starts_with("Math.")
            || fn_name_full.starts_with("JSON.")
            || fn_name_full.starts_with("console.")
            || fn_name_full.starts_with("process.")
        {
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
                    // Record as a potential sink since tainted data reached it
                    self.potential_sink_name = Some(fn_name_full.to_string());

                    // Use the semantic provider (or corpus-learned matching)
                    // for context-aware sink identification (qualified + suffix).
                    // When the provider is available, resolve the callee's
                    // receiver module so classify_sink can use import resolution.
                    let is_sink = if let Some(provider) = self.provider {
                        let resolved_module = provider.resolve_receiver_module(fn_name_full);
                        provider
                            .classify_sink(fn_name_full, resolved_module.as_deref())
                            .is_some()
                    } else {
                        self.source_sink.is_sink_expr(fn_name_full).is_some()
                    };
                    if is_sink {
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
                        path.push(format!("{fn_name_full}({arg_text})"));
                        return Some(CrossFileResult {
                            verified: true,
                            depth,
                            path: path.clone(),
                            detail: format!("Tainted data reaches sink '{fn_name_full}'"),
                            source_name: self.source_name.clone(),
                            sink_name: Some(fn_name_full.to_string()),
                            sink_line: Some(call_node.start_position().row as u32),
                        });
                    }
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
    fn check_callbacks(
        &mut self,
        call_node: Node,
        depth: usize,
        path: &mut Vec<String>,
    ) -> Option<CrossFileResult> {
        let callee = call_node
            .child_by_field_name("function")
            .or_else(|| call_node.child_by_field_name("callee"))
            .or_else(|| call_node.child(0))?;

        let fn_name = &self.source[callee.start_byte()..callee.end_byte()];

        if let Some(args_list) = call_node.child_by_field_name("arguments") {
            let mut cursor = args_list.walk();
            for arg in args_list.children(&mut cursor) {
                if matches!(arg.kind(), "(" | ")" | ",") {
                    continue;
                }

                if arg.kind() == "arrow_function" {
                    if let Some(body) = arg.child_by_field_name("body") {
                        let result = self.follow_taint(body, depth + 1, path);
                        if result.verified {
                            return Some(CrossFileResult {
                                verified: true,
                                depth: result.depth,
                                path: result.path,
                                detail: format!("Tainted data flows through callback to {fn_name}"),
                                source_name: self.source_name.clone(),
                                sink_name: Some(fn_name.to_string()),
                                sink_line: result.sink_line,
                            });
                        }
                    }
                }

                if arg.kind() == "function"
                    && let Some(body) = arg.child_by_field_name("body")
                {
                    let result = self.follow_taint(body, depth + 1, path);
                    if result.verified {
                        return Some(CrossFileResult {
                            verified: true,
                            depth: result.depth,
                            path: result.path,
                            detail: format!("Tainted data flows through callback to {fn_name}"),
                            source_name: self.source_name.clone(),
                            sink_name: Some(fn_name.to_string()),
                            sink_line: result.sink_line,
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
    fn check_promise_chain(
        &mut self,
        call_node: Node,
        depth: usize,
        path: &mut Vec<String>,
    ) -> Option<CrossFileResult> {
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

        let promise_methods = ["then", "catch", "finally", "tap"];
        if !promise_methods.contains(&method_name) {
            return None;
        }

        if let Some(object) = callee
            .child_by_field_name("object")
            .or_else(|| callee.child(0))
            && !self.is_node_tainted(object)
        {
            return None;
        }

        if let Some(args_list) = call_node.child_by_field_name("arguments") {
            let mut cursor = args_list.walk();
            for arg in args_list.children(&mut cursor) {
                if matches!(arg.kind(), "(" | ")" | ",") {
                    continue;
                }

                if arg.kind() == "arrow_function" {
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

                    if let Some(body) = arg.child_by_field_name("body") {
                        let result = self.follow_taint(body, depth + 1, path);
                        if result.verified {
                            return Some(CrossFileResult {
                                verified: true,
                                depth: result.depth,
                                path: result.path,
                                detail: format!(
                                    "Tainted data flows through .{method_name}() callback"
                                ),
                                source_name: self.source_name.clone(),
                                sink_name: Some(format!("{method_name}()")),
                                sink_line: result.sink_line,
                            });
                        }
                    }
                }

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
                            return Some(CrossFileResult {
                                verified: true,
                                depth: result.depth,
                                path: result.path,
                                detail: format!(
                                    "Tainted data flows through .{method_name}() callback"
                                ),
                                source_name: self.source_name.clone(),
                                sink_name: Some(format!("{method_name}()")),
                                sink_line: result.sink_line,
                            });
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if an object literal contains sink properties with tainted values.
    ///
    /// Example: `{ $where: \`this.userId == ${userId} && this.stocks > '${threshold}'\` }`
    /// The `$where` property is a MongoDB sink, and if its value (template literal)
    /// contains tainted data, this is a verified taint flow.
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    fn check_object_for_sink(
        &mut self,
        object_node: Node,
        depth: usize,
        path: &mut Vec<String>,
    ) -> Option<CrossFileResult> {
        let mut cursor = object_node.walk();
        for child in object_node.children(&mut cursor) {
            if child.kind() != "pair" {
                continue;
            }

            // Get the property name (key)
            let key_node = child.child_by_field_name("key")?;
            let key_name = &self.source[key_node.start_byte()..key_node.end_byte()];

            // Check if this property name is a known sink
            let is_sink = if let Some(provider) = self.provider {
                provider.classify_sink(key_name, None).is_some()
            } else {
                self.source_sink.is_sink_expr(key_name).is_some()
            };

            if !is_sink {
                continue;
            }

            // Check if the value contains tainted data
            let value_node = child.child_by_field_name("value")?;
            if self.is_node_tainted(value_node) {
                let value_text = &self.source[value_node.start_byte()..value_node.end_byte()];
                path.push(format!("{key_name}: {value_text}"));
                return Some(CrossFileResult {
                    verified: true,
                    depth,
                    path: path.clone(),
                    detail: format!("Tainted data flows into sink property '{key_name}'"),
                    source_name: self.source_name.clone(),
                    sink_name: Some(key_name.to_string()),
                    sink_line: Some(object_node.start_position().row as u32),
                });
            }
        }

        None
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Check if a node is tainted (variable reference or member expression).
    fn is_node_tainted(&self, node: Node) -> bool {
        self.is_node_tainted_inner(node)
    }

    fn is_node_tainted_inner(&self, node: Node) -> bool {
        match node.kind() {
            "conditional_expression" | "ternary_expression" => {
                // Iterate all children (skip operators ? and :)
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let child = cursor.node();
                        // Skip operator tokens
                        if !matches!(child.kind(), "?" | ":" | "?:" | "if" | "else" | ";" | ",") {
                            if self.is_node_tainted(child) {
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
            "identifier" => {
                let name = &self.source[node.start_byte()..node.end_byte()];
                // Check reaching-definitions first (more precise), then fall back to registry
                self.defs.is_tainted(name) || self.registry.is_tainted(name)
            }
            "member_expression" | "field_expression" => {
                // Check reaching-definitions first
                let full_name = &self.source[node.start_byte()..node.end_byte()];
                if self.defs.is_tainted(full_name) || self.registry.is_tainted(full_name) {
                    return true;
                }
                if let Some(object) = node.child_by_field_name("object").or_else(|| node.child(0)) {
                    let object_name = &self.source[object.start_byte()..object.end_byte()];
                    if self.defs.is_member_tainted(full_name, object_name) {
                        return true;
                    }
                }
                // Walk up the member-expression ancestor chain and check each prefix.
                // Resolves e.g. `req.body.login` when defs/registry contain `req.body` or `req`.
                let mut cur = node;
                loop {
                    let obj = cur.child_by_field_name("object").or_else(|| cur.child(0));
                    let Some(obj) = obj else { break };
                    let prefix = &self.source[obj.start_byte()..obj.end_byte()];
                    if self.defs.is_tainted(prefix) || self.registry.is_tainted(prefix) {
                        return true;
                    }
                    if matches!(obj.kind(), "member_expression" | "field_expression") {
                        cur = obj;
                    } else {
                        break;
                    }
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

                    // Check if a same-file callee's FunctionTaintSummary marks return as tainted
                    if self.callee_returns_tainted(short_name) {
                        return true;
                    }

                    // Return-value taint propagation from known source methods
                    if is_member {
                        if let Some(object) = c.child_by_field_name("object") {
                            if matches!(
                                short_name,
                                // HTTP request methods
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
                                    // DB/collection methods (MongoDB, Mongoose, Sequelize, Knex)
                                    | "collection"
                                    | "find"
                                    | "findOne"
                                    | "findById"
                                    | "findByIdAndUpdate"
                                    | "findByIdAndDelete"
                                    | "update"
                                    | "updateOne"
                                    | "updateMany"
                                    | "insertOne"
                                    | "insertMany"
                                    | "deleteOne"
                                    | "deleteMany"
                                    | "aggregate"
                                    | "exec"
                                    | "lean"
                                    | "sort"
                                    | "limit"
                                    | "skip"
                                    | "populate"
                                    | "select"
                                    | "where"
                                    | "then"
                                    // SQL query methods
                                    | "raw"
                                    | "insert"
                                    | "orderBy"
                                    | "groupBy"
                                    | "queryRaw"
                                    | "execute"
                                    // File system methods
                                    | "readFile"
                                    | "readFileSync"
                                    | "readdir"
                                    | "readdirSync"
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
            // Template literals with tainted expressions
            "template_string" | "template_literal" => {
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let child = cursor.node();
                        if child.kind() == "template_substitution"
                            && let Some(expr) = child.child(1)
                        {
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
            // Coalesce expressions (?? and ??=): tainted if either side is tainted
            "coalesce_expression" | "coalesce_assignment_expression" => {
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
                // Fallback: try positional children (lhs, rhs)
                // In tree-sitter-typescript: child(0)=lhs, child(2)=rhs
                if node.child_count() >= 3 {
                    if let Some(lhs) = node.child(0) {
                        if self.is_node_tainted(lhs) {
                            return true;
                        }
                    }
                    if let Some(rhs) = node.child(2) {
                        if self.is_node_tainted(rhs) {
                            return true;
                        }
                    }
                }
                false
            }
            // Optional chain expressions (?.): tainted if the object is tainted
            "optional_chain_expression" => {
                if let Some(object) = node.child_by_field_name("object") {
                    return self.is_node_tainted(object);
                }
                false
            }
            // Object literals: tainted if any property value is tainted
            "object" | "object_pattern" => {
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let child = cursor.node();
                        match child.kind() {
                            "pair" => {
                                if let Some(value) = child.child_by_field_name("value") {
                                    if self.is_node_tainted(value) {
                                        return true;
                                    }
                                }
                            }
                            "shorthand_property_identifier" | "identifier" => {
                                if self.is_node_tainted(child) {
                                    return true;
                                }
                            }
                            "spread_element" => {
                                if let Some(arg) = child.child(0) {
                                    if self.is_node_tainted(arg) {
                                        return true;
                                    }
                                }
                            }
                            _ => {}
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                false
            }
            // Array literals: tainted if any element is tainted
            "array" | "array_pattern" => {
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let child = cursor.node();
                        if !matches!(child.kind(), "[" | "]" | ",") {
                            if self.is_node_tainted(child) {
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
            // Parenthesized expressions: recurse on inner
            "parenthesized_expression" => {
                if let Some(inner) = node.child(0) {
                    return self.is_node_tainted(inner);
                }
                false
            }
            // TypeScript type assertions (as Cast, <Type>expr): check the inner expression
            "type_assertion" | "as_expression" | "satisfies_expression" => {
                if let Some(expr) = node.child(0) {
                    return self.is_node_tainted(expr);
                }
                false
            }
            // Unary expressions (e.g., !tainted): check operand
            "unary_expression" => {
                if let Some(operand) = node.child(0) {
                    return self.is_node_tainted(operand);
                }
                false
            }
            // Conditional expressions: tainted if either branch is tainted
            "conditional_expression" | "ternary_expression" => {
                // Try standard field names first
                if let Some(consequent) = node
                    .child_by_field_name("consequence")
                    .or_else(|| node.child_by_field_name("consequent"))
                {
                    if self.is_node_tainted(consequent) {
                        return true;
                    }
                }
                if let Some(alternate) = node.child_by_field_name("alternative") {
                    if self.is_node_tainted(alternate) {
                        return true;
                    }
                }
                // Fallback: iterate all children (skip operators ? and :)
                // conditional_expression children: condition ? consequence : alternative
                // But field names may vary between grammars, so just check all non-operator children
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let child = cursor.node();
                        // Skip operator tokens
                        if !matches!(child.kind(), "?" | ":" | "?:" | "if" | "else" | ";" | ",") {
                            if self.is_node_tainted(child) {
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
            // Assignment expressions used as values: check right side
            "assignment_expression" => {
                if let Some(right) = node.child_by_field_name("right") {
                    return self.is_node_tainted(right);
                }
                false
            }
            // Arrow/function expressions: check body
            "arrow_function" | "function" => {
                if let Some(body) = node.child_by_field_name("body") {
                    return self.is_node_tainted(body);
                }
                false
            }
            // Sequence expressions (comma operator): check last expression
            "sequence_expression" => {
                let mut last = None;
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        let child = cursor.node();
                        if !matches!(child.kind(), "," | "(" | ")") {
                            last = Some(child);
                        }
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                if let Some(expr) = last {
                    return self.is_node_tainted(expr);
                }
                false
            }
            _ => false,
        }
    }

    /// Try to resolve a same-file callee by name and check whether its
    /// pre-computed `FunctionTaintSummary` marks the return as tainted.
    fn callee_returns_tainted(&self, fn_name: &str) -> bool {
        let caller_file = &self.file_path;

        let engine_file_trees: FxHashMap<String, (&str, &tree_sitter::Tree)> = self
            .file_trees
            .iter()
            .map(|(k, (t, s, _))| (k.clone(), (s.as_str(), t)))
            .collect();

        let all_sym_entries: Vec<SymbolEntry> = self
            ._symbols
            .query_all()
            .into_iter()
            .map(|s| SymbolEntry {
                name: s.name.clone(),
                file_path: s.file_path.clone(),
                start_byte: s.start_byte,
                end_byte: s.end_byte,
                line: s.line,
                end_line: s.end_line,
                file_id: s.file_id.0,
            })
            .collect();

        let resolved = resolve_fn_definition(
            fn_name,
            caller_file,
            self.tree.root_node().start_position().row + 1,
            &self.registry,
            self.tree.root_node(),
            self.source,
            &all_sym_entries,
            &engine_file_trees,
        );

        if let Some(rf) = resolved {
            if rf.file_path == *caller_file {
                if let Some(summary) = self.data_flow.get_summary(caller_file, fn_name) {
                    return summary.propagates_return;
                }
            }
        }
        false
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

    use frensense_engine::corpus::source_sink::CorpusSourceSinkRegistry;

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
}
