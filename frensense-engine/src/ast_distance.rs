// SPDX-License-Identifier: MIT

//! AST Edit Distance (M2)
//!
//! Computes tree edit distance between structural skeletons of functions.
//! This catches structural differences that n-gram bag-of-words misses.

use tree_sitter::Node;

/// Extract the structural skeleton from an AST node.
/// Returns a list of node kinds (identifiers and literals removed).
pub fn extract_skeleton(
    root: Node,
    _source: &str,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) -> Vec<String> {
    let mut skeleton = Vec::new();
    extract_skeleton_recursive(root, &mut skeleton, spec);
    skeleton
}

/// Normalize node kind names so structurally equivalent constructs
/// produce identical skeleton sequences (for↔while, if↔switch, etc.).
fn normalize_kind<'a>(kind: &'a str, spec: Option<&dyn frensense_lang::LanguageSpec>) -> &'a str {
    if let Some(s) = spec {
        use frensense_lang::NodeRole;
        match s.classify(kind) {
            NodeRole::Loop => "loop_node",
            NodeRole::Branch => "branch_node",
            NodeRole::Try => "try_node",
            NodeRole::Catch => "catch_node",
            NodeRole::Finally => "finally_node",
            _ => kind,
        }
    } else {
        match kind {
            "while_statement" | "for_statement" | "for_in_statement" | "loop_expression"
            | "while_expression" | "for_expression" => "loop_node",
            "if_statement"
            | "if_expression"
            | "switch_statement"
            | "switch_expression"
            | "match_expression"
            | "match_statement"
            | "conditional_expression" => "branch_node",
            "catch_clause" | "catch_block" | "try_expression" | "try_statement" => "catch_node",
            other => other,
        }
    }
}

/// Recursively extract node kinds, skipping identifiers and literals.
fn extract_skeleton_recursive(
    node: Node,
    skeleton: &mut Vec<String>,
    spec: Option<&dyn frensense_lang::LanguageSpec>,
) {
    if skeleton.len() > 256 {
        return;
    }

    let kind = node.kind();

    // Skip leaf nodes that are identifiers or literals
    if node.child_count() == 0 {
        if kind == "identifier"
            || kind == "string"
            || kind == "number"
            || kind == "true"
            || kind == "false"
            || kind == "null"
            || kind == "undefined"
            || kind == "shorthand_property_identifier"
        {
            return;
        }
    }

    skeleton.push(normalize_kind(kind, spec).to_string());

    // Recurse into children
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            extract_skeleton_recursive(child, skeleton, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

/// Compute tree edit distance between two skeletons using a simplified algorithm.
/// Returns a normalized score between 0.0 (identical) and 1.0 (completely different).
///
/// This uses a greedy approximation of the Zhang-Shasha algorithm for efficiency.
pub fn tree_edit_distance(skeleton_a: &[u64], skeleton_b: &[u64]) -> f64 {
    if skeleton_a.is_empty() && skeleton_b.is_empty() {
        return 0.0;
    }
    if skeleton_a.is_empty() || skeleton_b.is_empty() {
        return 1.0;
    }

    // LCS-based edit distance (simplified but effective for our use case)
    let lcs_len = longest_common_subsequence(skeleton_a, skeleton_b);
    let max_len = skeleton_a.len().max(skeleton_b.len());

    // Normalize to 0-1 where 0 = identical, 1 = completely different
    1.0 - (lcs_len as f64 / max_len as f64)
}

/// Compute longest common subsequence length.
fn longest_common_subsequence(a: &[u64], b: &[u64]) -> usize {
    let m = a.len();
    let n = b.len();

    // Use space-optimized DP
    let mut prev = vec![0usize; n + 1];
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = prev[j].max(curr[j - 1]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }

    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_skeleton() {
        let source = "function foo(x) { return x + 1; }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let skeleton = extract_skeleton(root, source, None);
        assert!(!skeleton.is_empty());
        // Should not contain "foo" or "x" (identifiers)
        assert!(!skeleton.contains(&"identifier".to_string()));
    }

    fn hash(s: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = rustc_hash::FxHasher::default();
        s.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_tree_edit_distance_identical() {
        let a = vec![hash("function"), hash("block"), hash("return")];
        let b = vec![hash("function"), hash("block"), hash("return")];
        assert!((tree_edit_distance(&a, &b) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_tree_edit_distance_different() {
        let a = vec![hash("function"), hash("block"), hash("return")];
        let b = vec![hash("if"), hash("block"), hash("while")];
        let dist = tree_edit_distance(&a, &b);
        assert!(dist > 0.5);
    }

    #[test]
    fn test_tree_edit_distance_empty() {
        let a: Vec<u64> = vec![];
        let b = vec![hash("function")];
        assert!((tree_edit_distance(&a, &b) - 1.0).abs() < 0.001);
    }
}
