use crate::data_flow::alias::AliasTracker;
use frensense_lang::spec::{LanguageSpec, NodeRole};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Extracts (source_call, sink_call) data flow edges from a function.
pub fn extract_data_flows(
    func_node: Node<'_>,
    source: &str,
    spec: Option<&dyn LanguageSpec>,
) -> HashSet<(String, String)> {
    let mut flows = HashSet::new();
    let mut taints: HashMap<String, HashSet<String>> = HashMap::new();
    let mut alias_tracker = AliasTracker::new();

    // Fast iterative pre-order traversal
    let mut stack = vec![func_node];
    let mut visited_count = 0;

    while let Some(node) = stack.pop() {
        visited_count += 1;
        if visited_count > 1_000 {
            break;
        }
        let kind = node.kind();
        // When no spec is available, use raw kind matching as fallback.
        // When spec is available, classify via the spec to get field names.
        let dominated = match spec.map_or(None, |s| Some(s.classify(kind))) {
            Some(NodeRole::Declaration {
                name_field,
                value_field,
            }) => Some((
                node.child_by_field_name(name_field),
                node.child_by_field_name(value_field),
            )),
            Some(NodeRole::Assignment {
                lhs_field,
                rhs_field,
            }) => Some((
                node.child_by_field_name(lhs_field),
                node.child_by_field_name(rhs_field),
            )),
            None if kind == "variable_declarator" || kind == "assignment_expression" => Some((
                node.child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("left")),
                node.child_by_field_name("value")
                    .or_else(|| node.child_by_field_name("right")),
            )),
            _ => None,
        };

        if let Some((Some(l), Some(r))) = dominated {
            let l_name = extract_var_name(l, source, spec);
            let r_name = extract_var_name(r, source, spec);
            if !l_name.is_empty() && !r_name.is_empty() {
                alias_tracker.record_alias(&l_name, &r_name);
            }
            let r_taints = fast_evaluate_taint(r, source, &taints, &alias_tracker, spec);
            if !l_name.is_empty() && !r_taints.is_empty() {
                taints.entry(l_name).or_default().extend(r_taints);
            }
        } else {
            let is_call = spec.map_or(kind == "call_expression", |s| {
                matches!(s.classify(kind), NodeRole::Call { .. })
            });
            if is_call {
                let callee_field = spec.and_then(|s| match s.classify(kind) {
                    NodeRole::Call { callee_field, .. } => Some(callee_field),
                    _ => None,
                });
                let args_field = spec.and_then(|s| match s.classify(kind) {
                    NodeRole::Call { args_field, .. } => Some(args_field),
                    _ => None,
                });
                let callee = node
                    .child_by_field_name(callee_field.unwrap_or("function"))
                    .or_else(|| node.child_by_field_name("callee"));
                let args = node.child_by_field_name(args_field.unwrap_or("arguments"));

                if let (Some(c), Some(a)) = (callee, args) {
                    let sink_name = extract_callee_name(c, source, spec);
                    if !sink_name.is_empty() {
                        let arg_taints =
                            fast_evaluate_taint(a, source, &taints, &alias_tracker, spec);
                        for t in arg_taints {
                            if t != sink_name {
                                flows.insert((t.clone(), sink_name.clone()));
                            }
                        }
                    }
                }
            }
        }

        let mut children = Vec::new();
        let mut child_cursor = node.walk();
        for child in node.children(&mut child_cursor) {
            children.push(child);
        }
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }

    flows
}

fn fast_evaluate_taint(
    root: Node<'_>,
    source: &str,
    env: &HashMap<String, HashSet<String>>,
    alias_tracker: &AliasTracker,
    spec: Option<&dyn LanguageSpec>,
) -> HashSet<String> {
    let mut result = HashSet::new();
    let mut stack = vec![root];
    let mut visited_count = 0;

    // Avoid re-visiting nodes
    // Tree-sitter nodes don't implement Hash/Eq directly in a way we can easily use a HashSet for visited,
    // but a pre-order traversal of a tree without back-edges doesn't loop anyway.

    while let Some(node) = stack.pop() {
        visited_count += 1;
        if visited_count > 100 {
            break;
        }
        let kind = node.kind();
        let is_call = spec.map_or(kind == "call_expression", |s| {
            matches!(s.classify(kind), NodeRole::Call { .. })
        });
        if is_call {
            let callee_field = spec.and_then(|s| match s.classify(kind) {
                NodeRole::Call { callee_field, .. } => Some(callee_field),
                _ => None,
            });
            let callee = node
                .child_by_field_name(callee_field.unwrap_or("function"))
                .or_else(|| node.child_by_field_name("callee"));
            if let Some(c) = callee {
                let name = extract_callee_name(c, source, spec);
                if !name.is_empty() {
                    result.insert(name.clone());
                }
                let is_member = spec.map_or(c.kind() == "member_expression", |s| {
                    matches!(s.classify(c.kind()), NodeRole::MemberAccess { .. })
                });
                if is_member {
                    let object_field = spec.and_then(|s| match s.classify(c.kind()) {
                        NodeRole::MemberAccess { object_field, .. } => Some(object_field),
                        _ => None,
                    });
                    if let Some(obj) = c.child_by_field_name(object_field.unwrap_or("object")) {
                        stack.push(obj);
                    }
                }
            }
        } else {
            let is_await = spec.map_or(kind == "await_expression", |s| {
                matches!(s.classify(kind), NodeRole::Await)
            });
            if is_await {
                if let Some(arg) = node.child(1) {
                    stack.push(arg);
                }
            }
        }

        if matches!(
            kind,
            "identifier" | "field_identifier" | "property_identifier"
        ) {
            let name = source[node.start_byte()..node.end_byte()].to_string();
            if let Some(ts) = env.get(&name) {
                result.extend(ts.iter().cloned());
            } else {
                let mut found = false;
                for alias in alias_tracker.get_aliases(&name) {
                    if let Some(ts) = env.get(alias) {
                        result.extend(ts.iter().cloned());
                        found = true;
                    }
                }
                if !found {
                    result.insert(name);
                }
            }
        }

        // Push children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }

    result
}

fn extract_var_name(node: Node<'_>, source: &str, spec: Option<&dyn LanguageSpec>) -> String {
    let kind = node.kind();
    match spec.map_or(None, |s| Some(s.classify(kind))) {
        Some(NodeRole::Identifier) => source[node.start_byte()..node.end_byte()].to_string(),
        Some(NodeRole::MemberAccess { property_field, .. }) => {
            if let Some(prop) = node.child_by_field_name(property_field) {
                return source[prop.start_byte()..prop.end_byte()].to_string();
            }
            String::new()
        }
        None if matches!(kind, "identifier" | "field_identifier") => {
            source[node.start_byte()..node.end_byte()].to_string()
        }
        None if kind == "member_expression" => {
            if let Some(prop) = node.child_by_field_name("property") {
                return source[prop.start_byte()..prop.end_byte()].to_string();
            }
            String::new()
        }
        _ => String::new(),
    }
}

fn extract_callee_name(node: Node<'_>, source: &str, spec: Option<&dyn LanguageSpec>) -> String {
    let kind = node.kind();
    match spec.map_or(None, |s| Some(s.classify(kind))) {
        Some(NodeRole::Identifier) => source[node.start_byte()..node.end_byte()].to_string(),
        Some(NodeRole::MemberAccess {
            property_field,
            object_field,
            ..
        }) => {
            let prop = node
                .child_by_field_name(property_field)
                .or_else(|| node.child_by_field_name("field"))
                .map(|f| &source[f.start_byte()..f.end_byte()])
                .unwrap_or("");
            let obj = node
                .child_by_field_name(object_field)
                .map(
                    |o| match spec.map_or(None, |s| Some(s.classify(o.kind()))) {
                        Some(NodeRole::MemberAccess {
                            property_field: p_field,
                            ..
                        }) => o
                            .child_by_field_name(p_field)
                            .or_else(|| o.child_by_field_name("field"))
                            .map(|p| source[p.start_byte()..p.end_byte()].to_string())
                            .unwrap_or_default(),
                        Some(NodeRole::Identifier) => {
                            source[o.start_byte()..o.end_byte()].to_string()
                        }
                        None if o.kind() == "member_expression" => o
                            .child_by_field_name("property")
                            .or_else(|| o.child_by_field_name("field"))
                            .map(|p| source[p.start_byte()..p.end_byte()].to_string())
                            .unwrap_or_default(),
                        None if matches!(o.kind(), "identifier" | "field_identifier") => {
                            source[o.start_byte()..o.end_byte()].to_string()
                        }
                        _ => String::new(),
                    },
                )
                .unwrap_or_default();

            if obj.is_empty() {
                prop.to_string()
            } else {
                format!("{}.{}", obj, prop)
            }
        }
        None if matches!(kind, "identifier" | "field_identifier") => {
            source[node.start_byte()..node.end_byte()].to_string()
        }
        None if kind == "member_expression" => {
            let prop = node
                .child_by_field_name("property")
                .or_else(|| node.child_by_field_name("field"))
                .map(|f| &source[f.start_byte()..f.end_byte()])
                .unwrap_or("");
            let obj = node
                .child_by_field_name("object")
                .map(|o| match o.kind() {
                    "member_expression" => o
                        .child_by_field_name("property")
                        .or_else(|| o.child_by_field_name("field"))
                        .map(|p| source[p.start_byte()..p.end_byte()].to_string())
                        .unwrap_or_default(),
                    "identifier" | "field_identifier" => {
                        source[o.start_byte()..o.end_byte()].to_string()
                    }
                    _ => String::new(),
                })
                .unwrap_or_default();

            if obj.is_empty() {
                prop.to_string()
            } else {
                format!("{}.{}", obj, prop)
            }
        }
        None if kind == "scoped_identifier" => {
            let text = source[node.start_byte()..node.end_byte()].to_string();
            text.rsplit("::").next().unwrap_or(&text).to_string()
        }
        _ => String::new(),
    }
}
