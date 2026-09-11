// SPDX-License-Identifier: MIT

//! Top-level fingerprint extraction entry points.

use std::path::Path;
use tree_sitter::Node;

use super::ast_walkers::{
    collect_raw_call_names, collect_structural_markers, collect_type_usages, count_comment_bytes,
    extract_argument_call_types, extract_cf_sequence, extract_control_flow,
    extract_literal_patterns, extract_motif_hashes, extract_property_accesses,
    extract_semantic_markers, extract_tainted_calls,
};
use super::hashing::{
    normalize_token, split_name_segments, token_ngrams_positional, token_ngrams_sorted,
};
use super::types::FunctionFingerprint;
use crate::lang::Language;

// ---------------------------------------------------------------------------
// Signature helpers (live here because they use body_field / params_field)
// ---------------------------------------------------------------------------

fn extract_signature_tokens(node: Node<'_>, source: &str, body_field: &str) -> Vec<String> {
    let start = node.start_byte();
    let end = node
        .child_by_field_name(body_field)
        .map_or(node.end_byte(), |b| b.start_byte());
    source[start..end]
        .split_whitespace()
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
}

fn extract_param_types(node: Node<'_>, source: &str, params_field: &str) -> Vec<String> {
    let mut types = Vec::new();
    if let Some(params) = node.child_by_field_name(params_field) {
        let mut cursor = params.walk();
        loop {
            let n = cursor.node();
            if let Some(type_node) = n.child_by_field_name("type") {
                types.push(source[type_node.start_byte()..type_node.end_byte()].to_string());
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    types
}

// ---------------------------------------------------------------------------
// Main extraction
// ---------------------------------------------------------------------------

pub fn extract_fingerprints_with_nodes<'a>(
    root: Node<'a>,
    source_code: &str,
    path: &Path,
    fingerprints: &mut Vec<(FunctionFingerprint, Node<'a>)>,
    window_size: usize,
    import_map: Option<&crate::import_resolver::ImportMap>,
) {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let language = crate::parser::ext_to_language(ext).to_string();
    let spec = frensense_lang::spec_for_ext(ext);

    let lang: Language = match ext {
        "rs" => Language::Rust,
        "ts" | "tsx" => Language::TypeScript,
        "js" | "jsx" => Language::JavaScript,
        "c" | "h" => Language::C,
        "py" | "pyi" => Language::Python,
        "go" => Language::Go,
        _ => return,
    };

    let mut cursor = root.walk();

    loop {
        let node = cursor.node();
        let kind = node.kind();

        // Determine whether this node is a function via the spec, with a fallback.
        let is_function = spec.map(|s| s.is_function_node(kind)).unwrap_or_else(|| {
            matches!(
                kind,
                "function_item" | "function_declaration" | "method_definition" | "arrow_function"
            )
        });

        if is_function {
            // Resolve field names from the spec, falling back to sensible defaults.
            let (name_field, params_field, body_field) = spec
                .map(|s| match s.classify(kind) {
                    frensense_lang::NodeRole::Function {
                        name_field,
                        params_field,
                        body_field,
                        ..
                    } => (name_field, params_field, body_field),
                    _ => (Some("name"), "parameters", "body"),
                })
                .unwrap_or((Some("name"), "parameters", "body"));

            if let Some(body) = node.child_by_field_name(body_field) {
                // ----- Function name resolution -----
                let mut function_name = "anonymous".to_string();
                if let Some(nf) = name_field {
                    if let Some(name_node) = node.child_by_field_name(nf) {
                        function_name =
                            source_code[name_node.start_byte()..name_node.end_byte()].to_string();
                    } else if let Some(inferred) =
                        crate::route_registry::infer_function_name(node, source_code)
                    {
                        function_name = inferred;
                    }
                } else if let Some(inferred) =
                    crate::route_registry::infer_function_name(node, source_code)
                {
                    function_name = inferred;
                }

                // ----- Token n-grams -----
                let body_code = &source_code[body.start_byte()..body.end_byte()];
                let tokens: Vec<String> = body_code
                    .split_whitespace()
                    .filter(|t| !t.is_empty() && !t.starts_with("//"))
                    .map(|t| normalize_token(t).to_string())
                    .collect();

                let total_bytes = body.end_byte() - body.start_byte();
                let comment_bytes = count_comment_bytes(body, source_code);
                let sig_tokens = extract_signature_tokens(node, source_code, body_field);
                let param_types = extract_param_types(node, source_code, params_field);
                let name_segments = split_name_segments(&function_name);

                // Multi-scale n-grams: window sizes 3, 5, and 8
                let mut multi_scale_hashes = token_ngrams_positional(&tokens, window_size);
                multi_scale_hashes.extend(token_ngrams_positional(&tokens, window_size + 2));
                multi_scale_hashes.extend(token_ngrams_positional(&tokens, window_size + 5));

                // ----- AST-aware features -----
                let control_flow = extract_control_flow(body, source_code, spec);
                let control_flow_sequence = extract_cf_sequence(body, source_code, spec);
                let raw_call_names = collect_raw_call_names(body, source_code, spec);

                let mut api_calls_set = rustc_hash::FxHashSet::default();
                let mut api_call_segments_set = rustc_hash::FxHashSet::default();
                for name in &raw_call_names {
                    use std::hash::{Hash, Hasher};
                    let is_macro = name.starts_with("macro_");
                    let mut h = rustc_hash::FxHasher::default();
                    name.hash(&mut h);
                    api_calls_set.insert(h.finish());
                    if !is_macro {
                        if let Some(dot_pos) = name.rfind('.') {
                            let method = &name[dot_pos + 1..];
                            let mut h2 = rustc_hash::FxHasher::default();
                            method.hash(&mut h2);
                            api_call_segments_set.insert(h2.finish());
                        }
                    }
                }
                let mut api_calls: Vec<u64> = api_calls_set.into_iter().collect();
                api_calls.sort_unstable();
                let mut api_call_segments: Vec<u64> = api_call_segments_set.into_iter().collect();
                api_call_segments.sort_unstable();

                let property_accesses = extract_property_accesses(body, source_code, spec);
                let semantic_markers = extract_semantic_markers(
                    body,
                    source_code,
                    &api_calls,
                    &api_call_segments,
                    &property_accesses,
                );

                // ----- Taint analysis -----
                let param_names: Vec<String> = node
                    .child_by_field_name(params_field)
                    .map(|p| {
                        let mut names = Vec::new();
                        let mut c = p.walk();
                        if c.goto_first_child() {
                            loop {
                                let child = c.node();
                                if let Some(name) = child
                                    .child_by_field_name("pattern")
                                    .or_else(|| child.child_by_field_name("name"))
                                {
                                    let text = &source_code[name.start_byte()..name.end_byte()];
                                    if child.kind() == "identifier"
                                        || child.kind() == "required_parameter"
                                    {
                                        names.push(text.to_string());
                                    }
                                }
                                if !c.goto_next_sibling() {
                                    break;
                                }
                            }
                        }
                        names
                    })
                    .unwrap_or_default();

                let tainted_api_calls = extract_tainted_calls(
                    body,
                    source_code,
                    &param_names,
                    spec,
                    path.extension().and_then(|e| e.to_str()).unwrap_or(""),
                );
                let motif_hashes =
                    extract_motif_hashes(&raw_call_names, &crate::corpus::motifs::MOTIF_LOOKUP);
                let data_flow_path_hashes = crate::corpus::flow_fingerprint::extract_flow_paths(
                    body,
                    source_code,
                    import_map,
                    spec,
                );
                let argument_call_types = extract_argument_call_types(body, source_code, spec);
                let literal_pattern_hashes = extract_literal_patterns(body, source_code, spec);

                let skeleton = crate::ast_distance::extract_skeleton(body, source_code, spec);
                let mut skeleton_hashes = Vec::with_capacity(skeleton.len());
                for s in &skeleton {
                    use std::hash::{Hash, Hasher};
                    let mut hasher = rustc_hash::FxHasher::default();
                    s.hash(&mut hasher);
                    skeleton_hashes.push(hasher.finish());
                }

                let has_http_decorator =
                    crate::decorator::has_routing_decorator(node, source_code).is_some();
                let is_registered_handler =
                    crate::route_registry::is_function_registered_in_file(node, source_code, "")
                        || crate::route_registry::is_inline_registered_handler(node, source_code);

                let fp = FunctionFingerprint {
                    file_path: path.to_string_lossy().to_string(),
                    function_name,
                    line: node.start_position().row + 1,
                    language: language.clone(),
                    ngram_hashes: multi_scale_hashes.clone(),
                    weighted_ngram_hashes: multi_scale_hashes
                        .into_iter()
                        .map(|h| (h, 1.0))
                        .collect(),
                    signature_ngrams: token_ngrams_sorted(
                        &sig_tokens,
                        3.min(sig_tokens.len().max(1)),
                    ),
                    param_type_ngrams: token_ngrams_sorted(
                        &param_types,
                        2.min(param_types.len().max(1)),
                    ),
                    name_segments,
                    structural_markers: collect_structural_markers(body, source_code, lang),
                    type_usages: {
                        let mut tu = collect_type_usages(body, source_code);
                        tu.extend(crate::decorator::collect_param_decorator_types(
                            node,
                            source_code,
                        ));
                        tu
                    },
                    comment_density: if total_bytes > 0 {
                        comment_bytes as f64 / total_bytes as f64
                    } else {
                        0.0
                    },
                    semantic_markers,
                    skeleton,
                    skeleton_hashes,
                    control_flow_hashes: control_flow,
                    control_flow_sequence,
                    api_calls,
                    api_call_segments,
                    property_accesses,
                    motif_hashes,
                    data_flow_path_hashes,
                    raw_call_names,
                    param_names,
                    tainted_api_calls,
                    config_literal_hashes: Vec::new(),
                    argument_call_types,
                    literal_pattern_hashes,
                    has_http_decorator,
                    is_registered_handler,
                    export_handler_kind: crate::export_matcher::classify_exported_handler(
                        node,
                        source_code,
                        &path.to_string_lossy(),
                    ),
                };

                fingerprints.push((fp, node));
            } // end if let Some(body)
        } // end if is_function

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

pub fn extract_fingerprints(
    root: Node,
    source_code: &str,
    path: &Path,
    fingerprints: &mut Vec<FunctionFingerprint>,
    window_size: usize,
    import_map: Option<&crate::import_resolver::ImportMap>,
) {
    let mut with_nodes = Vec::new();
    extract_fingerprints_with_nodes(
        root,
        source_code,
        path,
        &mut with_nodes,
        window_size,
        import_map,
    );
    fingerprints.extend(with_nodes.into_iter().map(|(fp, _)| fp));
}
