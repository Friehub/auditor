/// Classify a taint source pattern by its likely origin.
/// Used during taint seeding to capture the correct TaintOrigin
/// so the SinkCategory × TaintOrigin relevance multiplier can downweight
/// mismatches (e.g. FileSystem data reaching an SQL sink).
#[must_use]
pub fn taint_source_origin(pattern: &str) -> frensense_engine::data_flow::TaintOrigin {
    if pattern.contains("process.env") {
        frensense_engine::data_flow::TaintOrigin::Environment
    } else if pattern.contains("req.file") || pattern.contains("req.files") {
        frensense_engine::data_flow::TaintOrigin::FileSystem
    } else {
        frensense_engine::data_flow::TaintOrigin::UserInput
    }
}

/// Collected features from a function node for constraint learning.
#[derive(Debug, Clone, Default)]
pub(crate) struct FunctionFeatures {
    calls: Vec<String>,
    node_types: Vec<String>,
    /// M2: Set if the function reads from a recognized taint source (user-controlled input)
    taint_sources: Vec<String>,
}

/// Collect features from a function node.
pub(crate) fn collect_function_features(
    node: tree_sitter::Node<'_>,
    source: &str,
    spec: Option<&dyn frensense_lang::spec::LanguageSpec>,
) -> FunctionFeatures {
    let mut features = FunctionFeatures::default();

    // Collect call targets
    let mut cursor = node.walk();
    loop {
        let n = cursor.node();
        if n.kind() == "call_expression" {
            if let Some(callee) = n
                .child_by_field_name("function")
                .or_else(|| n.child_by_field_name("callee"))
            {
                let target = source[callee.start_byte()..callee.end_byte()].to_string();
                features.calls.push(target);
            }
        }

        // Collect node types (only meaningful ones)
        let kind = n.kind();
        if !kind.is_empty() && !kind.starts_with("comment") {
            features.node_types.push(kind.to_string());
        }

        if cursor.goto_first_child() {
            continue;
        }
        let mut reached_root = false;
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                reached_root = true;
                break;
            }
        }
        if reached_root {
            break;
        }
    }

    features.calls.sort();
    features.calls.dedup();
    features.node_types.sort();
    features.node_types.dedup();

    // M2: Detect taint sources by scanning the raw source text of this function's span
    let func_src = &source[node.start_byte()..node.end_byte().min(source.len())];
    let patterns = spec
        .map(|s| s.known_source_patterns().to_vec())
        .unwrap_or_else(|| {
            frensense_engine::corpus::source_sink::always_register_source_patterns()
        });
    for pattern in patterns {
        if func_src.contains(pattern) {
            features.taint_sources.push(pattern.to_string());
        }
    }
    features.taint_sources.sort();
    features.taint_sources.dedup();

    features
}

/// Collect features from all function nodes in an AST.
pub(crate) fn collect_all_function_features(
    node: tree_sitter::Node<'_>,
    source: &str,
    out: &mut Vec<FunctionFeatures>,
    spec: Option<&dyn frensense_lang::spec::LanguageSpec>,
) {
    let kind = node.kind();
    // Use spec-based classification for function nodes with fallback
    let is_fn = spec.map(|s| s.is_function_node(kind)).unwrap_or_else(|| {
        matches!(
            kind,
            "function_item"
                | "function_declaration"
                | "method_definition"
                | "arrow_function"
                | "function"
                | "generator_function"
                | "function_signature"
                | "method_declaration"
        )
    });
    if is_fn {
        out.push(collect_function_features(node, source, spec));
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_all_function_features(child, source, out, spec);
        }
    }
}

/// Learn semantic constraints from pre-collected features.
pub(crate) fn learn_from_features(
    pos_features: &[FunctionFeatures],
    neg_features: &[FunctionFeatures],
) -> frensense_engine::corpus::semantic::LearnedConstraints {
    if pos_features.is_empty() || neg_features.is_empty() {
        return frensense_engine::corpus::semantic::LearnedConstraints::default();
    }

    // Collect all call targets from positives and negatives
    let pos_calls: std::collections::HashSet<&str> = pos_features
        .iter()
        .flat_map(|f| f.calls.iter().map(std::string::String::as_str))
        .collect();
    let neg_calls: std::collections::HashSet<&str> = neg_features
        .iter()
        .flat_map(|f| f.calls.iter().map(std::string::String::as_str))
        .collect();

    // Find calls in ALL positives but NOT in any negative
    let mut required_calls: Vec<String> = pos_features[0]
        .calls
        .iter()
        .filter(|call| {
            pos_features.iter().all(|f| f.calls.contains(*call))
                && !neg_calls.contains(&call.as_str())
        })
        .cloned()
        .collect();

    // M2: Auto-promote taint sources to required_calls when positives have taint
    // and negatives do not - eliminates FP on non-user-controlled code paths.
    let pos_has_taint = pos_features.iter().any(|f| !f.taint_sources.is_empty());
    let neg_has_taint = neg_features.iter().any(|f| !f.taint_sources.is_empty());
    if pos_has_taint && !neg_has_taint {
        // Collect taint sources present in any positive but absent from all negatives
        let neg_taint: std::collections::HashSet<&str> = neg_features
            .iter()
            .flat_map(|f| f.taint_sources.iter().map(std::string::String::as_str))
            .collect();
        for f in pos_features {
            for src in &f.taint_sources {
                if !neg_taint.contains(src.as_str()) && !required_calls.contains(src) {
                    required_calls.push(src.clone());
                }
            }
        }
    }

    // Find calls in ALL negatives but NOT in any positive
    let forbidden_calls: Vec<String> = neg_features[0]
        .calls
        .iter()
        .filter(|call| {
            neg_features.iter().all(|f| f.calls.contains(*call))
                && !pos_calls.contains(&call.as_str())
        })
        .cloned()
        .collect();

    // Same for node types
    let pos_nts: std::collections::HashSet<&str> = pos_features
        .iter()
        .flat_map(|f| f.node_types.iter().map(std::string::String::as_str))
        .collect();
    let neg_nts: std::collections::HashSet<&str> = neg_features
        .iter()
        .flat_map(|f| f.node_types.iter().map(std::string::String::as_str))
        .collect();

    // Filter out noise node types
    let noise: std::collections::HashSet<&str> = [
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
        "formal_parameters",
        "type_annotation",
    ]
    .iter()
    .copied()
    .collect();

    let required_node_types: Vec<String> = pos_features[0]
        .node_types
        .iter()
        .filter(|nt| {
            !noise.contains(nt.as_str())
                && pos_features.iter().all(|f| f.node_types.contains(*nt))
                && !neg_nts.contains(&nt.as_str())
        })
        .cloned()
        .collect();

    let forbidden_node_types: Vec<String> = neg_features[0]
        .node_types
        .iter()
        .filter(|nt| {
            !noise.contains(nt.as_str())
                && neg_features.iter().all(|f| f.node_types.contains(*nt))
                && !pos_nts.contains(&nt.as_str())
        })
        .cloned()
        .collect();

    frensense_engine::corpus::semantic::LearnedConstraints {
        required_calls,
        forbidden_calls,
        required_node_types,
        forbidden_node_types,
        required_taint_flows: Vec::new(),
    }
}
