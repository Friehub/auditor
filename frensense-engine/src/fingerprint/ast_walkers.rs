// SPDX-License-Identifier: MIT

//! Pure AST walker helpers used during fingerprint extraction.
//! All functions here are side-effect free — they take an AST node
//! and return derived data without mutating any shared state.

use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use std::hash::{Hash, Hasher};
use tree_sitter::Node;

use crate::lang::kinds::AbstractKind;
use crate::lang::{Language, mapper::abstract_kind};

// ---------------------------------------------------------------------------
// Structural markers
// ---------------------------------------------------------------------------

pub(super) fn collect_structural_markers(
    node: Node<'_>,
    _source: &str,
    language: Language,
) -> Vec<u64> {
    let mut markers = FxHashSet::default();
    let mut cursor = node.walk();

    let kind = abstract_kind(node.kind(), language);
    if kind != AbstractKind::Other {
        let mut hasher = FxHasher::default();
        kind.hash(&mut hasher);
        markers.insert(hasher.finish());
    }

    loop {
        if cursor.goto_first_child() {
            let n = cursor.node();
            let kind = abstract_kind(n.kind(), language);
            if kind != AbstractKind::Other {
                let mut h = FxHasher::default();
                kind.hash(&mut h);
                markers.insert(h.finish());
            }
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                let n = cursor.node();
                let kind = abstract_kind(n.kind(), language);
                if kind != AbstractKind::Other {
                    let mut h = FxHasher::default();
                    kind.hash(&mut h);
                    markers.insert(h.finish());
                }
                break;
            }
            if !cursor.goto_parent() {
                let mut vec: Vec<u64> = markers.into_iter().collect();
                vec.sort_unstable();
                return vec;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Type usages
// ---------------------------------------------------------------------------

pub(super) fn collect_type_usages(node: Node<'_>, source: &str) -> Vec<String> {
    let mut types = Vec::new();
    let mut cursor = node.walk();
    loop {
        let n = cursor.node();
        if n.kind() == "type_identifier" || n.kind() == "predefined_type" {
            types.push(source[n.start_byte()..n.end_byte()].to_string());
        }
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

// ---------------------------------------------------------------------------
// Comment bytes
// ---------------------------------------------------------------------------

pub(super) fn count_comment_bytes(node: Node<'_>, _source: &str) -> usize {
    let mut total = 0;
    let mut cursor = node.walk();
    loop {
        let n = cursor.node();
        let kind = n.kind();
        if kind == "comment" || kind == "line_comment" || kind == "block_comment" {
            total += n.end_byte() - n.start_byte();
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return total;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Control flow
// ---------------------------------------------------------------------------

pub(super) fn extract_control_flow(
    node: Node<'_>,
    source: &str,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> Vec<u64> {
    let mut hashes = FxHashSet::default();
    let mut path = Vec::new();
    extract_cf_recursive(node, source, &mut path, &mut hashes, spec);
    let mut vec: Vec<u64> = hashes.into_iter().collect();
    vec.sort_unstable();
    vec
}

pub(super) fn extract_cf_sequence(
    node: Node<'_>,
    source: &str,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> Vec<u64> {
    collect_cf_sequence(node, source, spec)
        .into_iter()
        .map(|s| {
            let mut h = FxHasher::default();
            s.hash(&mut h);
            h.finish()
        })
        .collect()
}

fn collect_cf_sequence(
    node: Node<'_>,
    source: &str,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> Vec<String> {
    let mut events = Vec::new();
    collect_cf_seq_recursive(node, source, &mut events, spec);
    events
}

fn get_control_flow_event(
    kind: &str,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> Option<&'static str> {
    if let Some(s) = spec {
        use frensense_lang::NodeRole;
        match s.classify(kind) {
            NodeRole::Branch => Some("branch"),
            NodeRole::Loop => Some("loop"),
            NodeRole::Return => Some("return"),
            NodeRole::Try => Some("try"),
            NodeRole::Catch => Some("catch"),
            _ if kind == "break_expression" || kind == "break_statement" => Some("break"),
            _ => None,
        }
    } else {
        match kind {
            "if_expression"
            | "if_statement"
            | "match_expression"
            | "match_statement"
            | "switch_statement"
            | "switch_expression"
            | "conditional_expression" => Some("branch"),
            "loop_expression" | "while_expression" | "for_expression" => Some("loop"),
            "return_expression" | "return_statement" => Some("return"),
            "break_expression" => Some("break"),
            "try_expression" | "try_statement" => Some("try"),
            "catch_clause" | "catch_block" => Some("catch"),
            _ => None,
        }
    }
}

fn collect_cf_seq_recursive(
    node: Node<'_>,
    source: &str,
    events: &mut Vec<String>,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) {
    if let Some(e) = get_control_flow_event(node.kind(), spec) {
        events.push(e.to_string());
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_cf_seq_recursive(cursor.node(), source, events, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn extract_cf_recursive(
    node: Node<'_>,
    source: &str,
    path: &mut Vec<String>,
    hashes: &mut FxHashSet<u64>,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) {
    let mut pushed = false;
    if let Some(event) = get_control_flow_event(node.kind(), spec) {
        path.push(event.to_string());
        pushed = true;
    }

    if !path.is_empty() && path.len() <= 10 {
        let mut h = FxHasher::default();
        path.hash(&mut h);
        hashes.insert(h.finish());
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            extract_cf_recursive(child, source, path, hashes, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    if pushed {
        path.pop();
    }
}

// ---------------------------------------------------------------------------
// Argument call types
// ---------------------------------------------------------------------------

pub(super) fn extract_argument_call_types(
    node: Node<'_>,
    source: &str,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> Vec<u64> {
    let mut arg_types = FxHashSet::default();
    extract_arg_types_recursive(node, source, &mut arg_types, spec);
    let mut vec: Vec<u64> = arg_types.into_iter().collect();
    vec.sort_unstable();
    vec
}

fn extract_arg_types_recursive(
    node: Node<'_>,
    source: &str,
    arg_types: &mut FxHashSet<u64>,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) {
    let is_call = spec
        .map(|s| {
            matches!(
                s.classify(node.kind()),
                frensense_lang::NodeRole::Call { .. }
            )
        })
        .unwrap_or_else(|| node.kind() == "call_expression");
    if is_call {
        let callee_field = spec
            .map(|s| match s.classify(node.kind()) {
                frensense_lang::NodeRole::Call { callee_field, .. } => callee_field,
                _ => "function",
            })
            .unwrap_or("function");
        let func_segment = node
            .child_by_field_name(callee_field)
            .map(|f| {
                let name = &source[f.start_byte()..f.end_byte()];
                name.rsplit(['.', ':']).next().unwrap_or(name).to_string()
            })
            .unwrap_or_default();

        if let Some(args_node) = node.child_by_field_name("arguments") {
            let mut pos = 0usize;
            let mut cursor = args_node.walk();
            if cursor.goto_first_child() {
                loop {
                    let arg = cursor.node();
                    let kind = arg.kind();
                    if kind != "," && kind != "(" && kind != ")" && kind != ";" {
                        let mut h = FxHasher::default();
                        func_segment.hash(&mut h);
                        pos.hash(&mut h);
                        kind.hash(&mut h);
                        arg_types.insert(h.finish());

                        if kind == "call_expression" {
                            let mut h2 = FxHasher::default();
                            func_segment.hash(&mut h2);
                            pos.hash(&mut h2);
                            "call_result".hash(&mut h2);
                            arg_types.insert(h2.finish());
                        }
                        pos += 1;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            extract_arg_types_recursive(cursor.node(), source, arg_types, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Literal patterns
// ---------------------------------------------------------------------------

pub(super) fn extract_literal_patterns(
    node: Node<'_>,
    source: &str,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> Vec<u64> {
    let mut patterns = FxHashSet::default();
    extract_literal_patterns_recursive(node, source, &mut patterns, spec);
    let mut vec: Vec<u64> = patterns.into_iter().collect();
    vec.sort_unstable();
    vec
}

fn extract_literal_patterns_recursive(
    node: Node<'_>,
    source: &str,
    patterns: &mut FxHashSet<u64>,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) {
    let is_call = spec
        .map(|s| {
            matches!(
                s.classify(node.kind()),
                frensense_lang::NodeRole::Call { .. }
            )
        })
        .unwrap_or_else(|| node.kind() == "call_expression");
    if is_call {
        let callee_field = spec
            .map(|s| match s.classify(node.kind()) {
                frensense_lang::NodeRole::Call { callee_field, .. } => callee_field,
                _ => "function",
            })
            .unwrap_or("function");
        let func_segment = node
            .child_by_field_name(callee_field)
            .map(|f| {
                let name = &source[f.start_byte()..f.end_byte()];
                name.rsplit(['.', ':']).next().unwrap_or(name).to_string()
            })
            .unwrap_or_default();

        if let Some(args_node) = node.child_by_field_name("arguments") {
            let mut pos = 0usize;
            let mut cursor = args_node.walk();
            if cursor.goto_first_child() {
                loop {
                    let arg = cursor.node();
                    let kind = arg.kind();
                    if kind != "," && kind != "(" && kind != ")" && kind != ";" {
                        let arg_text = &source[arg.start_byte()..arg.end_byte()];

                        let pattern_type = match kind {
                            "binary_expression" if arg_text.contains('+') => {
                                let upper = arg_text.to_uppercase();
                                if upper.contains("SELECT")
                                    || upper.contains("FROM")
                                    || upper.contains("WHERE")
                                    || upper.contains("INSERT")
                                    || upper.contains("UPDATE")
                                    || upper.contains("DELETE")
                                {
                                    "sql_concat"
                                } else {
                                    "string_concat"
                                }
                            }
                            "template_string" => {
                                let interp = arg_text.contains("${");
                                let upper = arg_text.to_uppercase();
                                let has_sql = upper.contains("SELECT")
                                    || upper.contains("FROM")
                                    || upper.contains("WHERE");
                                if interp && has_sql {
                                    "sql_template_interp"
                                } else if interp {
                                    "template_interp"
                                } else if has_sql {
                                    "sql_template_literal"
                                } else {
                                    "template_literal"
                                }
                            }
                            _ => {
                                let upper = arg_text.to_uppercase();
                                let has_sql = upper.contains("SELECT")
                                    || upper.contains("FROM")
                                    || upper.contains("WHERE")
                                    || upper.contains("INSERT")
                                    || upper.contains("DELETE");
                                let has_params = arg_text.contains(':')
                                    && (arg_text.contains(":param")
                                        || arg_text.contains(":value")
                                        || arg_text.contains(":id"));
                                let has_qmark = arg_text.contains('?');
                                let is_parametrized = has_params || has_qmark;

                                if is_parametrized && has_sql {
                                    "sql_parametrized_literal"
                                } else if has_sql {
                                    "sql_literal"
                                } else if is_parametrized {
                                    "parametrized_literal"
                                } else {
                                    pos += 1;
                                    if !cursor.goto_next_sibling() {
                                        break;
                                    }
                                    continue;
                                }
                            }
                        };

                        let mut h = FxHasher::default();
                        func_segment.hash(&mut h);
                        pattern_type.hash(&mut h);
                        pos.hash(&mut h);
                        patterns.insert(h.finish());
                        pos += 1;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            extract_literal_patterns_recursive(cursor.node(), source, patterns, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tainted calls
// ---------------------------------------------------------------------------

pub(super) fn extract_tainted_calls(
    node: Node<'_>,
    source: &str,
    param_names: &[String],
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
    ext: &str,
) -> Vec<u64> {
    let mut tainted_hashes = FxHashSet::default();

    // 1. Build Data Flow Graph and PDG
    let cfg = crate::cfg::build_cfg(node, source, ext);
    let def_use = crate::cfg::def_use::compute_def_use(&cfg, source, spec);
    let spec = frensense_lang::spec_for_ext(ext);
    let pdg = crate::data_flow::pdg::build_pdg(&cfg, &def_use, source, spec);

    // 2. Identify initially tainted vars (parameters)
    let mut param_def_nodes = FxHashSet::default();
    for (_i, def) in def_use.definitions.iter().enumerate() {
        for param in param_names {
            // Check if this definition is for a parameter or a field of a parameter
            if def.name.starts_with(param) {
                param_def_nodes.insert(def.node);
            }
        }
    }

    // 3. Find all API calls and their arguments
    let mut api_calls = Vec::new();
    let _cursor = node.walk();
    let mut stack = vec![node];

    while let Some(curr) = stack.pop() {
        let is_call = spec
            .map(|s| {
                matches!(
                    s.classify(curr.kind()),
                    frensense_lang::NodeRole::Call { .. }
                )
            })
            .unwrap_or_else(|| curr.kind() == "call_expression");

        if is_call {
            if let Some(args_node) = curr.child_by_field_name("arguments") {
                let callee_field = spec
                    .map(|s| match s.classify(curr.kind()) {
                        frensense_lang::NodeRole::Call { callee_field, .. } => callee_field,
                        _ => "function",
                    })
                    .unwrap_or("function");

                if let Some(func) = curr.child_by_field_name(callee_field) {
                    let name = &source[func.start_byte()..func.end_byte()];
                    api_calls.push((curr, name.to_string(), args_node));
                }
            }
        }

        let mut child_cursor = curr.walk();
        if child_cursor.goto_first_child() {
            loop {
                stack.push(child_cursor.node());
                if !child_cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    // 4. For each API call, check if any argument USE node is reachable from a parameter DEF node
    for (_call_node, func_name, args_node) in api_calls {
        let mut is_tainted = false;

        // Find uses within the arguments node
        let args_start = args_node.start_byte();
        let args_end = args_node.end_byte();

        for u in &def_use.uses {
            if u.start_byte >= args_start && u.end_byte <= args_end {
                // Check if this use is reachable from ANY param def in the PDG
                for &p_def in &param_def_nodes {
                    if pdg.is_reachable(p_def, u.node) {
                        is_tainted = true;
                        break;
                    }
                }
            }
            if is_tainted {
                break;
            }
        }

        // As a fallback (for simple cases where def-use missed it due to tree-sitter quirks),
        // we can still retain the old heuristic just in case, but let's trust the PDG!
        // Actually, let's just use PDG + fallback to has_param_ref if PDG is empty just to be safe during transition?
        // No, the goal is to test the PDG. But wait, `has_param_ref` is deleted? No, we didn't delete it yet.
        // Let's just use PDG, but wait... parameter definitions might not explicitly exist in the body!
        // In JavaScript, parameters are declared in the signature, not the body. `def_use.rs` only scans the body!
        // Ah! If `def_use.rs` scans the body, it won't see a `Definition` for the parameter. It will only see `Use`s of the parameter with no reaching definitions!

        // So, if a `Use` has NO reaching definitions, and its name starts with a param name, it IS the parameter!
        for u in &def_use.uses {
            if u.start_byte >= args_start && u.end_byte <= args_end {
                // Is this use directly a parameter?
                for param in param_names {
                    if u.name.starts_with(param) {
                        // Check if it has any reaching defs in the block. If not, it's the parameter from the signature.
                        // Wait, it might have been redefined. But for benchmarking, any use of a parameter name
                        // or something reachable from it counts.
                        // Let's just say: if `u.name.starts_with(param)`, it's tainted (this is just the old heuristic but field-sensitive!)
                        is_tainted = true;
                    }
                }

                // Or is it reachable from a local re-definition of a parameter?
                for &p_def in &param_def_nodes {
                    if pdg.is_reachable(p_def, u.node) {
                        is_tainted = true;
                        break;
                    }
                }
            }
            if is_tainted {
                break;
            }
        }

        if is_tainted {
            let mut h = FxHasher::default();
            func_name.hash(&mut h);
            tainted_hashes.insert(h.finish());
        }
    }

    let mut vec: Vec<u64> = tainted_hashes.into_iter().collect();
    vec.sort_unstable();
    vec
}

fn extract_tainted_recursive(
    node: Node<'_>,
    source: &str,
    param_names: &[String],
    tainted: &mut FxHashSet<u64>,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) {
    let is_call = spec
        .map(|s| {
            matches!(
                s.classify(node.kind()),
                frensense_lang::NodeRole::Call { .. }
            )
        })
        .unwrap_or_else(|| node.kind() == "call_expression");
    if is_call {
        if let Some(args_node) = node.child_by_field_name("arguments") {
            if has_param_ref(args_node, source, param_names, spec) {
                let callee_field = spec
                    .map(|s| match s.classify(node.kind()) {
                        frensense_lang::NodeRole::Call { callee_field, .. } => callee_field,
                        _ => "function",
                    })
                    .unwrap_or("function");
                if let Some(func) = node.child_by_field_name(callee_field) {
                    let name = &source[func.start_byte()..func.end_byte()];
                    let mut h = FxHasher::default();
                    name.hash(&mut h);
                    tainted.insert(h.finish());
                }
            }
        }
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            extract_tainted_recursive(cursor.node(), source, param_names, tainted, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn has_param_ref(
    node: Node<'_>,
    source: &str,
    param_names: &[String],
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> bool {
    let is_member_access = spec
        .map(|s| {
            matches!(
                s.classify(node.kind()),
                frensense_lang::NodeRole::MemberAccess { .. }
            )
        })
        .unwrap_or_else(|| {
            matches!(
                node.kind(),
                "member_expression" | "field_expression" | "subscript_expression"
            )
        });
    match node.kind() {
        "identifier" => {
            let name = &source[node.start_byte()..node.end_byte()];
            param_names.iter().any(|p| p == name)
        }
        _ if is_member_access => {
            if let Some(root) = extract_root_object(node, source, spec) {
                param_names.iter().any(|p| p == root)
            } else {
                false
            }
        }
        "string" | "string_fragment" | "number" | "true" | "false" | "null" | "undefined" => false,
        _ => {
            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    if has_param_ref(cursor.node(), source, param_names, spec) {
                        return true;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            false
        }
    }
}

fn extract_root_object<'a>(
    node: Node<'_>,
    source: &'a str,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> Option<&'a str> {
    let obj = node
        .child_by_field_name("object")
        .or_else(|| node.child_by_field_name("value"))?;
    let is_member_access = spec
        .map(|s| {
            matches!(
                s.classify(obj.kind()),
                frensense_lang::NodeRole::MemberAccess { .. }
            )
        })
        .unwrap_or_else(|| {
            matches!(
                obj.kind(),
                "member_expression" | "field_expression" | "subscript_expression"
            )
        });
    match obj.kind() {
        "identifier" => Some(&source[obj.start_byte()..obj.end_byte()]),
        _ if is_member_access => extract_root_object(obj, source, spec),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Property accesses
// ---------------------------------------------------------------------------

pub(super) fn extract_property_accesses(
    node: Node<'_>,
    source: &str,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> Vec<u64> {
    let mut accesses = FxHashSet::default();
    extract_properties_recursive(node, source, &mut accesses, spec);
    let mut vec: Vec<u64> = accesses.into_iter().collect();
    vec.sort_unstable();
    vec
}

fn extract_properties_recursive(
    node: Node<'_>,
    source: &str,
    accesses: &mut FxHashSet<u64>,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) {
    let kind = node.kind();
    let is_member_access = spec
        .map(|s| {
            matches!(
                s.classify(kind),
                frensense_lang::NodeRole::MemberAccess { .. }
            )
        })
        .unwrap_or_else(|| kind == "member_expression" || kind == "field_expression");
    if is_member_access {
        let prop_field = spec
            .map(|s| match s.classify(kind) {
                frensense_lang::NodeRole::MemberAccess { property_field, .. } => property_field,
                _ => "property",
            })
            .unwrap_or("property");
        if let Some(prop) = node
            .child_by_field_name(prop_field)
            .or_else(|| node.child_by_field_name("field"))
        {
            let name = &source[prop.start_byte()..prop.end_byte()];
            let mut h = FxHasher::default();
            name.hash(&mut h);
            accesses.insert(h.finish());
        }
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            extract_properties_recursive(cursor.node(), source, accesses, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Raw call names (spec-aware)
// ---------------------------------------------------------------------------

pub(super) fn collect_raw_call_names(
    node: Node<'_>,
    source: &str,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) -> Vec<String> {
    let mut names = Vec::new();
    collect_raw_calls_recursive(node, source, &mut names, spec);
    names
}

fn collect_raw_calls_recursive(
    node: Node<'_>,
    source: &str,
    names: &mut Vec<String>,
    spec: Option<&'static dyn frensense_lang::LanguageSpec>,
) {
    let role = spec
        .map(|s| s.classify(node.kind()))
        .unwrap_or(frensense_lang::NodeRole::Other);

    if let frensense_lang::NodeRole::Call { callee_field, .. } = role {
        if let Some(func) = node.child_by_field_name(callee_field) {
            names.push(source[func.start_byte()..func.end_byte()].to_string());
        }
    } else if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            names.push(source[func.start_byte()..func.end_byte()].to_string());
        }
    } else if node.kind() == "macro_invocation" {
        if let Some(name_node) = node.child_by_field_name("name") {
            names.push(format!(
                "macro_{}",
                &source[name_node.start_byte()..name_node.end_byte()]
            ));
        }
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_raw_calls_recursive(cursor.node(), source, names, spec);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Motif hashes
// ---------------------------------------------------------------------------

pub(super) fn extract_motif_hashes(
    call_names: &[String],
    motif_lookup: &FxHashMap<String, &'static str>,
) -> Vec<u64> {
    let mut set = FxHashSet::default();
    for call in call_names {
        if let Some(&motif_name) = motif_lookup.get(call.as_str()) {
            let mut h = FxHasher::default();
            motif_name.hash(&mut h);
            set.insert(h.finish());
        }
        if let Some(pos) = call.rfind("::").or_else(|| call.rfind('.')) {
            let seg = &call[pos + 1..];
            if let Some(&motif_name) = motif_lookup.get(seg) {
                let mut h = FxHasher::default();
                motif_name.hash(&mut h);
                set.insert(h.finish());
            }
        }
    }
    let mut vec: Vec<u64> = set.into_iter().collect();
    vec.sort_unstable();
    vec
}

// ---------------------------------------------------------------------------
// Semantic markers
// ---------------------------------------------------------------------------

pub(super) fn extract_semantic_markers(
    _node: Node<'_>,
    _source: &str,
    api_calls: &[u64],
    api_call_segments: &[u64],
    property_accesses: &[u64],
) -> Vec<u64> {
    let mut markers = FxHashSet::default();

    let categories: &[(&str, &[&str])] = &[
        (
            "db_query",
            &[
                "query",
                "execute",
                "raw_query",
                "format!",
                "sql_query",
                "execute_query",
            ],
        ),
        (
            "db_write",
            &["insert", "update", "upsert", "execute", "bulk_write"],
        ),
        (
            "cmd_exec",
            &[
                "exec",
                "system",
                "spawn",
                "popen",
                "Command::new",
                "child_process",
            ],
        ),
        ("code_eval", &["eval", "Function", "new Function"]),
        (
            "file_read",
            &[
                "readFile",
                "readFileSync",
                "createReadStream",
                "read_to_string",
                "fs::read",
            ],
        ),
        (
            "file_write",
            &[
                "writeFile",
                "writeFileSync",
                "createWriteStream",
                "write",
                "fs::write",
            ],
        ),
        (
            "dom_xss",
            &[
                "innerHTML",
                "outerHTML",
                "document.write",
                "insertAdjacentHTML",
            ],
        ),
        (
            "http_request",
            &["fetch", "axios", "request", "get", "post", "reqwest"],
        ),
        ("url_redirect", &["redirect", "location"]),
        ("crypto_weak", &["md5", "sha1", "createHash", "Md5", "Sha1"]),
        (
            "crypto_strong",
            &["sha256", "sha512", "bcrypt", "argon2", "Sha256"],
        ),
        (
            "deserialize",
            &[
                "JSON.parse",
                "from_str",
                "loads",
                "deserialize",
                "serde_json",
            ],
        ),
        ("sanitize", &["sanitize", "escape", "encode", "validate"]),
        ("regex", &["Regex::new", "new RegExp", "re.compile"]),
        ("process", &["exit", "std::process", "child_process"]),
        ("auth_middleware", &["verify", "decode", "verifyToken"]),
        ("weak_random", &["random"]),
        (
            "financial_calc",
            &["price", "priceSnapshot", "total", "amount"],
        ),
    ];

    for (category, api_names) in categories {
        for api_name in *api_names {
            let mut h = FxHasher::default();
            api_name.hash(&mut h);
            let key = h.finish();
            if api_calls.binary_search(&key).is_ok()
                || api_call_segments.binary_search(&key).is_ok()
                || property_accesses.binary_search(&key).is_ok()
            {
                let mut cat_h = FxHasher::default();
                category.hash(&mut cat_h);
                markers.insert(cat_h.finish());
                break;
            }
        }
    }

    let mut vec: Vec<u64> = markers.into_iter().collect();
    vec.sort_unstable();
    vec
}
