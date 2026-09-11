// SPDX-License-Identifier: MIT

//! Semantic filters for corpus pattern matching.
//!
//! Fingerprint-based matching alone produces false positives because structurally
//! similar code can have different semantics. For example, `setTimeout(() => abort())`
//! looks like `.then(res => res.json())` to a fingerprint matcher, but only the latter
//! is a promise chain.
//!
//! Semantic filters check AST-level constraints before scoring, ensuring patterns
//! only match code that actually exhibits the bug they're designed to detect.

use tree_sitter::Node;

/// Semantic constraint for a corpus pattern.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct SemanticFilter {
    /// Only match functions containing calls to these targets.
    /// E.g., `["fetch", ".then"]` for promise patterns.
    pub contains_call_to: Vec<String>,

    /// Only match functions whose name matches this regex pattern.
    /// E.g., `^sanitize` for sanitizer passthrough patterns.
    pub function_name_regex: Option<String>,

    /// Only match functions that do NOT contain calls to these targets.
    /// E.g., `[".catch"]` for `promise_catch` (must NOT have .catch).
    pub must_not_contain_call_to: Vec<String>,

    /// Only match if the function body contains specific AST node types.
    /// E.g., `["await_expression"]` for async patterns.
    pub contains_node_type: Vec<String>,

    /// Only match if the function does NOT contain these node types.
    pub must_not_contain_node_type: Vec<String>,

    /// Optional list of data flow paths that must exist in the function.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub required_taint_flows: Vec<(String, String)>,

    /// Only match if the function name does NOT match any of these regexes.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub must_not_match_function_name: Vec<String>,

    /// Only match if the file path does NOT match any of these glob patterns.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub must_not_match_file_path_pattern: Vec<String>,

    /// Only match if the source file contains import statements from these packages.
    /// E.g., `["@remix-run/react", "next/image"]` for Remix/Next.js patterns.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub contains_import: Vec<String>,

    /// Only match if the source file does NOT contain import statements from these packages.
    /// E.g., `["next", "@remix-run/react"]` so Express patterns reject Next.js/Remix files.
    /// Inverse of `contains_import`.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub must_not_contain_import: Vec<String>,
}

impl SemanticFilter {
    /// Returns true if this filter is empty (no constraints).
    pub fn is_empty(&self) -> bool {
        self.contains_call_to.is_empty()
            && self.function_name_regex.is_none()
            && self.must_not_contain_call_to.is_empty()
            && self.contains_node_type.is_empty()
            && self.must_not_contain_node_type.is_empty()
            && self.must_not_match_function_name.is_empty()
            && self.must_not_match_file_path_pattern.is_empty()
            && self.contains_import.is_empty()
            && self.must_not_contain_import.is_empty()
    }

    pub fn matches(
        &self,
        func_node: Node<'_>,
        source: &str,
        file_path: Option<&str>,
        extracted_flows: Option<&std::collections::HashSet<(String, String)>>,
        spec: Option<&dyn frensense_lang::spec::LanguageSpec>,
    ) -> bool {
        if self.is_empty() {
            return true;
        }

        // Check file path patterns
        if let Some(path) = file_path {
            if !self.must_not_match_file_path_pattern.is_empty() {
                for pattern in &self.must_not_match_file_path_pattern {
                    // Very simple glob handling for *, or just string contains
                    let p = pattern.trim_start_matches('*');
                    let p = p.trim_end_matches('*');
                    if path.contains(p) {
                        return false;
                    }
                }
            }
        }

        // Check contains_import — scan file source for import statements (case-insensitive)
        if !self.contains_import.is_empty() {
            let source_lower = source.to_lowercase();
            let has_import = self.contains_import.iter().any(|pkg| {
                let pkg_lower = pkg.to_lowercase();
                let from_pattern = format!("from '{pkg_lower}'");
                let from_pattern2 = format!("from \"{pkg_lower}\"");
                let req_pattern = format!("require('{pkg_lower}')");
                let req_pattern2 = format!("require(\"{pkg_lower}\")");
                source_lower.contains(&from_pattern)
                    || source_lower.contains(&from_pattern2)
                    || source_lower.contains(&req_pattern)
                    || source_lower.contains(&req_pattern2)
            });
            if !has_import {
                return false;
            }
        }

        // Check must_not_contain_import — reject if file imports any of these packages (case-insensitive)
        if !self.must_not_contain_import.is_empty() {
            let source_lower = source.to_lowercase();
            let has_forbidden_import = self.must_not_contain_import.iter().any(|pkg| {
                let pkg_lower = pkg.to_lowercase();
                let from_pattern = format!("from '{pkg_lower}'");
                let from_pattern2 = format!("from \"{pkg_lower}\"");
                let req_pattern = format!("require('{pkg_lower}')");
                let req_pattern2 = format!("require(\"{pkg_lower}\")");
                source_lower.contains(&from_pattern)
                    || source_lower.contains(&from_pattern2)
                    || source_lower.contains(&req_pattern)
                    || source_lower.contains(&req_pattern2)
            });
            if has_forbidden_import {
                return false;
            }
        }

        let func_name = extract_function_name(func_node, source);

        // Check function name regex
        if let Some(ref pattern) = self.function_name_regex {
            if let Some(name) = &func_name {
                if !regex_match(name, pattern) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check forbidden function names
        if !self.must_not_match_function_name.is_empty() {
            if let Some(name) = &func_name {
                for pattern in &self.must_not_match_function_name {
                    if regex_match(name, pattern) {
                        return false;
                    }
                }
            }
        }

        let _func_src = &source[func_node.start_byte()..func_node.end_byte()];

        // Check contains_call_to — uses the same text-based extractor as the
        // auto-filter (extract_call_targets) which skips comments and non-call
        // text. This keeps the filter consistent with what the auto-filter learned.
        if !self.contains_call_to.is_empty() {
            let calls = extract_ast_call_targets(func_node, source);
            let has_match = self.contains_call_to.iter().any(|target| {
                calls
                    .iter()
                    .any(|call| call.to_lowercase().contains(&target.to_lowercase()))
            });
            if !has_match {
                return false;
            }
        }

        // Check must_not_contain_call_to (same text-based extractor)
        if !self.must_not_contain_call_to.is_empty() {
            let calls = extract_ast_call_targets(func_node, source);
            let has_forbidden = self.must_not_contain_call_to.iter().any(|target| {
                calls
                    .iter()
                    .any(|call| call.to_lowercase().contains(&target.to_lowercase()))
            });
            if has_forbidden {
                return false;
            }
        }

        // Check contains_node_type
        if !self.contains_node_type.is_empty() {
            let node_types = collect_node_types(func_node);
            let has_match = self
                .contains_node_type
                .iter()
                .any(|nt| node_types.iter().any(|t| t == nt));
            if !has_match {
                return false;
            }
        }

        // Check must_not_contain_node_type
        if !self.must_not_contain_node_type.is_empty() {
            let node_types = collect_node_types(func_node);
            let has_forbidden = self
                .must_not_contain_node_type
                .iter()
                .any(|nt| node_types.iter().any(|t| t == nt));
            if has_forbidden {
                return false;
            }
        }

        // required_taint_flows is a precision constraint: every required flow
        // MUST be present, otherwise reject. func_node and source are always
        // available in this function, so we extract flows on demand rather than
        // silently passing through when the caller did not provide them.
        if !self.required_taint_flows.is_empty() {
            let flows = match extracted_flows {
                Some(flows) => flows,
                None => {
                    &crate::corpus::data_flow_extractor::extract_data_flows(func_node, source, spec)
                }
            };
            for req_flow in &self.required_taint_flows {
                if !flows.contains(req_flow) {
                    return false;
                }
            }
        }

        true
    }
}

/// Extract the function/method name from a function AST node.
fn extract_function_name(node: Node<'_>, source: &str) -> Option<String> {
    // Look for name child
    for i in 0..node.child_count() {
        let child = node.child(i)?;
        match child.kind() {
            "identifier" | "field_identifier" | "property_identifier" => {
                return Some(source[child.start_byte()..child.end_byte()].to_string());
            }
            "name" => {
                // TypeScript function_declaration name
                return Some(source[child.start_byte()..child.end_byte()].to_string());
            }
            _ => {}
        }
    }

    // For arrow functions, check parent
    if node.kind() == "arrow_function" || node.kind() == "function" {
        let parent = node.parent()?;
        match parent.kind() {
            "variable_declarator" => {
                let name_node = parent.child_by_field_name("name")?;
                return Some(source[name_node.start_byte()..name_node.end_byte()].to_string());
            }
            "assignment_expression" => {
                let left = parent.child_by_field_name("left")?;
                return Some(source[left.start_byte()..left.end_byte()].to_string());
            }
            _ => {}
        }
    }

    None
}

/// Collect all call targets (function names or method names) in a function.
fn collect_call_targets(node: Node<'_>, source: &str) -> Vec<String> {
    let mut calls = Vec::new();
    let mut cursor = node.walk();

    loop {
        let n = cursor.node();

        if n.kind() == "call_expression" {
            // TypeScript/Rust tree-sitter grammars use "function" field for the callee
            if let Some(callee) = n
                .child_by_field_name("function")
                .or_else(|| n.child_by_field_name("callee"))
            {
                let target = source[callee.start_byte()..callee.end_byte()].to_string();
                calls.push(target);
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
                return calls;
            }
        }
    }
}

/// Collect all node types in a subtree.
fn collect_node_types(node: Node<'_>) -> Vec<String> {
    let mut types = Vec::new();
    let mut cursor = node.walk();

    loop {
        let n = cursor.node();
        types.push(n.kind().to_string());

        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return types;
            }
        }
    }
}

/// Learned semantic constraints from positive/negative example pairs.
///
/// Instead of manually writing TOML filters, we automatically extract
/// what makes positives different from negatives by comparing their
/// AST features (call targets, node types).
#[derive(Debug, Clone, Default)]
pub struct LearnedConstraints {
    /// Call targets that appear in ALL positives but NOT in the corresponding negatives.
    /// These become `contains_call_to` constraints.
    pub required_calls: Vec<String>,
    /// Call targets that appear in ALL negatives but NOT in the positives.
    /// These become `must_not_contain_call_to` constraints.
    pub forbidden_calls: Vec<String>,
    /// Node types that appear in ALL positives but NOT in negatives.
    pub required_node_types: Vec<String>,
    /// Node types that appear in ALL negatives but NOT in positives.
    pub forbidden_node_types: Vec<String>,
    /// Data flow edges that appear in ALL positives.
    pub required_taint_flows: Vec<(String, String)>,
}

impl LearnedConstraints {
    pub fn is_empty(&self) -> bool {
        self.required_calls.is_empty()
            && self.forbidden_calls.is_empty()
            && self.required_node_types.is_empty()
            && self.forbidden_node_types.is_empty()
            && self.required_taint_flows.is_empty()
    }

    /// Convert to a `SemanticFilter` for use in pattern matching.
    pub fn to_filter(&self) -> SemanticFilter {
        SemanticFilter {
            contains_call_to: self.required_calls.clone(),
            must_not_contain_call_to: self.forbidden_calls.clone(),
            contains_node_type: self.required_node_types.clone(),
            must_not_contain_node_type: self.forbidden_node_types.clone(),
            required_taint_flows: self.required_taint_flows.clone(),
            function_name_regex: None,
            must_not_match_function_name: Vec::new(),
            must_not_match_file_path_pattern: Vec::new(),
            contains_import: Vec::new(),
            must_not_contain_import: Vec::new(),
        }
    }
}

/// Learn semantic constraints by comparing positive and negative examples.
///
/// For each feature (call targets, node types):
/// - If it appears in ALL positives but NOT in ANY negative → required
/// - If it appears in ALL negatives but NOT in ANY positive → forbidden
///
/// This automatically captures what makes the buggy code different from the fix.
pub fn learn_constraints(
    positive_nodes: &[(tree_sitter::Node<'_>, &str)],
    negative_nodes: &[(tree_sitter::Node<'_>, &str)],
) -> LearnedConstraints {
    if positive_nodes.is_empty() || negative_nodes.is_empty() {
        return LearnedConstraints::default();
    }

    // Collect features from all positives
    let mut pos_call_sets: Vec<Vec<String>> = Vec::new();
    let mut pos_node_sets: Vec<Vec<String>> = Vec::new();
    let mut pos_flow_sets: Vec<Vec<(String, String)>> = Vec::new();
    for (node, source) in positive_nodes {
        let mut calls: Vec<String> = collect_call_targets(*node, source);
        calls.sort();
        calls.dedup();
        pos_call_sets.push(calls);

        let mut nodes = collect_node_types(*node);
        nodes.sort();
        nodes.dedup();
        pos_node_sets.push(nodes);

        let mut flows = crate::corpus::data_flow_extractor::extract_data_flows(*node, source, None)
            .into_iter()
            .collect::<Vec<_>>();
        flows.sort();
        flows.dedup();
        pos_flow_sets.push(flows);
    }

    // Collect features from all negatives
    let mut neg_call_sets: Vec<Vec<String>> = Vec::new();
    let mut neg_node_sets: Vec<Vec<String>> = Vec::new();
    let mut neg_flow_sets: Vec<Vec<(String, String)>> = Vec::new();
    for (node, source) in negative_nodes {
        let mut calls: Vec<String> = collect_call_targets(*node, source);
        calls.sort();
        calls.dedup();
        neg_call_sets.push(calls);

        let mut nodes = collect_node_types(*node);
        nodes.sort();
        nodes.dedup();
        neg_node_sets.push(nodes);

        let mut flows = crate::corpus::data_flow_extractor::extract_data_flows(*node, source, None)
            .into_iter()
            .collect::<Vec<_>>();
        flows.sort();
        flows.dedup();
        neg_flow_sets.push(flows);
    }

    // Find call targets in ALL positives
    let pos_call_universe: std::collections::HashSet<&str> = pos_call_sets
        .iter()
        .flatten()
        .map(std::string::String::as_str)
        .collect();

    let required_calls: Vec<String> = pos_call_universe
        .iter()
        .filter(|call| {
            // Must be in EVERY positive
            pos_call_sets.iter().all(|set| set.iter().any(|c| c == *call))
                // Must NOT be in ANY negative
                && !neg_call_sets.iter().any(|set| set.iter().any(|c| c == *call))
        })
        .map(std::string::ToString::to_string)
        .collect();

    // Find call targets in ALL negatives (but not in positives)
    let neg_call_universe: std::collections::HashSet<&str> = neg_call_sets
        .iter()
        .flatten()
        .map(std::string::String::as_str)
        .collect();

    let forbidden_calls: Vec<String> = neg_call_universe
        .iter()
        .filter(|call| {
            neg_call_sets
                .iter()
                .all(|set| set.iter().any(|c| c == *call))
                && !pos_call_sets
                    .iter()
                    .any(|set| set.iter().any(|c| c == *call))
        })
        .map(std::string::ToString::to_string)
        .collect();

    // Same for node types
    let pos_node_universe: std::collections::HashSet<&str> = pos_node_sets
        .iter()
        .flatten()
        .map(std::string::String::as_str)
        .collect();

    let required_node_types: Vec<String> = pos_node_universe
        .iter()
        .filter(|nt| {
            pos_node_sets.iter().all(|set| set.iter().any(|t| t == *nt))
                && !neg_node_sets.iter().any(|set| set.iter().any(|t| t == *nt))
        })
        .map(std::string::ToString::to_string)
        .collect();

    let neg_node_universe: std::collections::HashSet<&str> = neg_node_sets
        .iter()
        .flatten()
        .map(std::string::String::as_str)
        .collect();

    let forbidden_node_types: Vec<String> = neg_node_universe
        .iter()
        .filter(|nt| {
            neg_node_sets.iter().all(|set| set.iter().any(|t| t == *nt))
                && !pos_node_sets.iter().any(|set| set.iter().any(|t| t == *nt))
        })
        .map(std::string::ToString::to_string)
        .collect();

    // Filter out noise: skip very common node types that don't discriminate
    let noise_nodes: std::collections::HashSet<&str> = [
        "program",
        "statement_block",
        "expression_statement",
        "return_statement",
        "if_statement",
        "variable_declaration",
        "identifier",
        "call_expression",
        "member_expression",
        "string",
        "number",
        "true",
        "false",
        "null",
        "template_string",
        "binary_expression",
        "unary_expression",
        "parenthesized_expression",
        "comma_expression",
    ]
    .iter()
    .copied()
    .collect();

    let mut c = LearnedConstraints {
        required_calls,
        forbidden_calls,
        required_node_types: required_node_types
            .into_iter()
            .filter(|nt| !noise_nodes.contains(nt.as_str()))
            .collect(),
        forbidden_node_types: forbidden_node_types
            .into_iter()
            .filter(|nt| !noise_nodes.contains(nt.as_str()))
            .collect(),
        required_taint_flows: Vec::new(),
    };

    // Data flow constraints
    let pos_flow_universe: std::collections::HashSet<&(String, String)> =
        pos_flow_sets.iter().flatten().collect();

    c.required_taint_flows = pos_flow_universe
        .into_iter()
        .filter(|flow| {
            pos_flow_sets
                .iter()
                .all(|set| set.iter().any(|f| f == *flow))
        })
        .cloned()
        .collect();

    c
}

/// Match `text` against `pattern` using the `regex` crate.
///
/// Patterns support full regex syntax (`.` `*` `[]` `^` `$` alternation, etc.).
/// An invalid pattern is treated as a non-match rather than panicking, so a
/// typo like `^sanitiseHtml$` yields a clean miss instead of a substring hit.
fn regex_match(text: &str, pattern: &str) -> bool {
    match regex::Regex::new(pattern) {
        Ok(re) => re.is_match(text),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ts(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn test_function_name_regex() {
        let tree = parse_ts("function sanitizeHtml(input: string) { return input; }");
        let func = tree.root_node().child(0).unwrap();

        let filter = SemanticFilter {
            function_name_regex: Some("^sanitize".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(
            func,
            "function sanitizeHtml(input: string) { return input; }",
            None,
            None,
            None
        ));

        let filter2 = SemanticFilter {
            function_name_regex: Some("^escape".to_string()),
            ..Default::default()
        };
        assert!(!filter2.matches(
            func,
            "function sanitizeHtml(input: string) { return input; }",
            None,
            None,
            None
        ));
    }

    #[test]
    fn test_contains_call_to() {
        let tree = parse_ts("function foo() { fetch('/api').then(r => r.json()); }");
        let func = tree.root_node().child(0).unwrap();

        let filter = SemanticFilter {
            contains_call_to: vec!["fetch".to_string()],
            ..Default::default()
        };
        assert!(filter.matches(
            func,
            "function foo() { fetch('/api').then(r => r.json()); }",
            None,
            None,
            None
        ));

        let filter2 = SemanticFilter {
            contains_call_to: vec!["axios".to_string()],
            ..Default::default()
        };
        assert!(!filter2.matches(
            func,
            "function foo() { fetch('/api').then(r => r.json()); }",
            None,
            None,
            None
        ));
    }

    #[test]
    fn test_must_not_contain_call_to() {
        let tree = parse_ts("function foo() { fetch('/api').then(r => r.json()); }");
        let func = tree.root_node().child(0).unwrap();

        let filter = SemanticFilter {
            contains_call_to: vec!["fetch".to_string()],
            must_not_contain_call_to: vec![".catch".to_string()],
            ..Default::default()
        };
        assert!(filter.matches(
            func,
            "function foo() { fetch('/api').then(r => r.json()); }",
            None,
            None,
            None
        ));

        let tree2 =
            parse_ts("function foo() { fetch('/api').then(r => r.json()).catch(e => {}); }");
        let func2 = tree2.root_node().child(0).unwrap();
        assert!(!filter.matches(
            func2,
            "function foo() { fetch('/api').then(r => r.json()).catch(e => {}); }",
            None,
            None,
            None
        ));
    }
}

pub fn extract_ast_call_targets(node: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut targets = std::collections::HashSet::new();
    let _cursor = node.walk();

    // Perform a pre-order traversal
    let mut visit_stack = vec![node];
    while let Some(n) = visit_stack.pop() {
        if n.kind() == "call_expression" {
            if let Some(callee) = n
                .child_by_field_name("function")
                .or_else(|| n.child_by_field_name("callee"))
            {
                if let Ok(text) =
                    std::str::from_utf8(&source.as_bytes()[callee.start_byte()..callee.end_byte()])
                {
                    targets.insert(text.to_string());
                }
            }
        }

        let mut child_cursor = n.walk();
        for child in n.children(&mut child_cursor) {
            visit_stack.push(child);
        }
    }

    targets
}
