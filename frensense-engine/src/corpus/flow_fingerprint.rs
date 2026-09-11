// SPDX-License-Identifier: MIT

//! Lightweight intra-function data-flow path fingerprinting.
//!
//! Does NOT require a full data-flow graph. Operates purely on the AST
//! using def-use tracking within a single function body. The resulting
//! path hashes are invariant to variable renaming, helper extraction,
//! and formatting changes.

use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use std::hash::{Hash, Hasher};
use tree_sitter::Node;

use crate::corpus::motifs::MOTIF_LOOKUP;
use frensense_lang::spec::{LanguageSpec, NodeRole};

/// A source-to-sink path represented as a sequence of abstract node labels.
#[derive(Debug, Clone)]
pub struct FlowPath {
    /// E.g. ["UserInputSource", "assignment", "call", "CommandExecutionSink"]
    pub labels: Vec<&'static str>,
}

impl FlowPath {
    pub fn hash(&self) -> u64 {
        let mut h = FxHasher::default();
        self.labels.hash(&mut h);
        h.finish()
    }
}

/// Extract lightweight data-flow path hashes from a function body.
///
/// Algorithm:
/// 1. Find all assignments where the RHS contains a known UserInputSource.
/// 2. For each assigned variable, trace forward through the body to see
///    if it reaches a known sink (CommandExecutionSink, SqlSink, etc.).
/// 3. Record the abstract path: source_motif → [intermediate_motifs] → sink_motif.
/// 4. Hash each path.
///
/// This is O(n²) in the number of assignments × calls, which is fine for
/// function bodies (n < 200 in practice).
pub fn extract_flow_paths(
    body: Node<'_>,
    source: &str,
    import_map: Option<&crate::import_resolver::ImportMap>,
    spec: Option<&dyn LanguageSpec>,
) -> Vec<u64> {
    let lookup = &*MOTIF_LOOKUP;

    // Step 1: collect all identifiers that are assigned from a source motif
    let tainted_vars = collect_tainted_vars(body, source, lookup, import_map, spec);
    if tainted_vars.is_empty() {
        return Vec::new();
    }

    // Step 2: find sink calls that use tainted variables as arguments
    let mut path_hashes = FxHashSet::default();
    find_sink_paths(
        body,
        source,
        &tainted_vars,
        lookup,
        import_map,
        spec,
        &mut path_hashes,
    );

    let mut vec: Vec<u64> = path_hashes.into_iter().collect();
    vec.sort_unstable();
    vec
}

/// Returns a map of variable name → source motif name for variables
/// assigned from a recognized source.
fn collect_tainted_vars(
    node: Node<'_>,
    source: &str,
    lookup: &FxHashMap<String, &'static str>,
    import_map: Option<&crate::import_resolver::ImportMap>,
    spec: Option<&dyn LanguageSpec>,
) -> FxHashMap<String, &'static str> {
    let mut tainted: FxHashMap<String, &'static str> = FxHashMap::default();
    collect_tainted_recursive(node, source, lookup, import_map, spec, &mut tainted);
    tainted
}

fn collect_tainted_recursive(
    node: Node<'_>,
    source: &str,
    lookup: &FxHashMap<String, &'static str>,
    import_map: Option<&crate::import_resolver::ImportMap>,
    spec: Option<&dyn LanguageSpec>,
    tainted: &mut FxHashMap<String, &'static str>,
) {
    let kind = node.kind();
    let is_decl_or_assign = spec.map_or(
        kind == "variable_declarator" || kind == "assignment_expression",
        |s| {
            matches!(
                s.classify(kind),
                NodeRole::Declaration { .. } | NodeRole::Assignment { .. }
            )
        },
    );

    // Variable declaration with initializer: `let cmd = req.body.cmd`
    if is_decl_or_assign {
        if let Some(s) = spec {
            match s.classify(kind) {
                NodeRole::Declaration {
                    name_field,
                    value_field,
                } => {
                    if let (Some(name_node), Some(value_node)) = (
                        node.child_by_field_name(name_field),
                        node.child_by_field_name(value_field),
                    ) {
                        let var_name = &source[name_node.start_byte()..name_node.end_byte()];
                        if rhs_references_source(value_node, source, lookup, spec) {
                            tainted.insert(var_name.to_string(), "UserInputSource");
                        } else if let Some(cat) =
                            rhs_is_sink_call(value_node, source, lookup, import_map, spec)
                        {
                            if cat == crate::corpus::source_sink::SinkCategory::SqlInjection
                                || cat == crate::corpus::source_sink::SinkCategory::NoSqlInjection
                            {
                                tainted.insert(var_name.to_string(), "DatabaseSource");
                            }
                        }
                    }
                }
                NodeRole::Assignment {
                    lhs_field,
                    rhs_field,
                } => {
                    if let (Some(name_node), Some(value_node)) = (
                        node.child_by_field_name(lhs_field),
                        node.child_by_field_name(rhs_field),
                    ) {
                        let var_name = &source[name_node.start_byte()..name_node.end_byte()];
                        if rhs_references_source(value_node, source, lookup, spec) {
                            tainted.insert(var_name.to_string(), "UserInputSource");
                        } else if let Some(cat) =
                            rhs_is_sink_call(value_node, source, lookup, import_map, spec)
                        {
                            if cat == crate::corpus::source_sink::SinkCategory::SqlInjection
                                || cat == crate::corpus::source_sink::SinkCategory::NoSqlInjection
                            {
                                tainted.insert(var_name.to_string(), "DatabaseSource");
                            }
                        }
                    }
                }
                _ => {}
            }
        } else {
            // Fallback: raw kind matching when no spec is available
            if let (Some(name_node), Some(value_node)) = (
                node.child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("left")),
                node.child_by_field_name("value")
                    .or_else(|| node.child_by_field_name("right")),
            ) {
                let var_name = &source[name_node.start_byte()..name_node.end_byte()];
                if rhs_references_source(value_node, source, lookup, spec) {
                    tainted.insert(var_name.to_string(), "UserInputSource");
                } else if let Some(cat) =
                    rhs_is_sink_call(value_node, source, lookup, import_map, spec)
                {
                    if cat == crate::corpus::source_sink::SinkCategory::SqlInjection
                        || cat == crate::corpus::source_sink::SinkCategory::NoSqlInjection
                    {
                        tainted.insert(var_name.to_string(), "DatabaseSource");
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_tainted_recursive(cursor.node(), source, lookup, import_map, spec, tainted);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

/// Helper to determine if a node is a call expression to a known sink.
fn rhs_is_sink_call(
    node: Node<'_>,
    source: &str,
    lookup: &FxHashMap<String, &'static str>,
    import_map: Option<&crate::import_resolver::ImportMap>,
    spec: Option<&dyn LanguageSpec>,
) -> Option<crate::corpus::source_sink::SinkCategory> {
    let is_call = spec.map_or(node.kind() == "call_expression", |s| {
        matches!(s.classify(node.kind()), NodeRole::Call { .. })
    });

    if is_call {
        let callee_field = spec.and_then(|s| match s.classify(node.kind()) {
            NodeRole::Call { callee_field, .. } => Some(callee_field),
            _ => None,
        });
        if let Some(func) = node.child_by_field_name(callee_field.unwrap_or("function")) {
            let call_name = &source[func.start_byte()..func.end_byte()];

            // Resolve to motif
            let sink_motif = lookup.get(call_name).copied().or_else(|| {
                call_name
                    .rfind("::")
                    .or_else(|| call_name.rfind('.'))
                    .and_then(|p| lookup.get(&call_name[p + 1..]).copied())
            });

            if let Some(m) = sink_motif {
                if m == "SqlSink" {
                    return Some(crate::corpus::source_sink::SinkCategory::SqlInjection);
                } else if m == "NoSqlSink" {
                    return Some(crate::corpus::source_sink::SinkCategory::NoSqlInjection);
                }
            }

            // Fallback: check if the receiver comes from a known package sink category
            if let Some(imap) = import_map {
                if let Some(receiver) = call_name.split('.').next() {
                    if let Some(pkg) = imap.resolve(receiver) {
                        if let Some(cat) =
                            crate::semantic::package_sink_category_from_spec(pkg, spec)
                        {
                            return Some(cat);
                        }
                    }
                }
            }
        }
    }

    // Check if it's an await expression wrapping a call
    let is_await = spec.map_or(node.kind() == "await_expression", |s| {
        matches!(s.classify(node.kind()), NodeRole::Await)
    });
    if is_await {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if let Some(cat) = rhs_is_sink_call(cursor.node(), source, lookup, import_map, spec)
                {
                    return Some(cat);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    None
}

/// Returns true if the RHS subtree contains a node whose full text is a known
/// UserInputSource member, walking only reference nodes and never descending
/// into string literal content.
fn rhs_references_source(
    node: Node<'_>,
    source: &str,
    lookup: &FxHashMap<String, &'static str>,
    spec: Option<&dyn LanguageSpec>,
) -> bool {
    let kind = node.kind();

    // Never treat literal text (string contents, comments, numbers) as a source
    // reference. Template substitution expressions `${x}` are handled because we
    // only skip the *fragment* nodes, not the substitution.
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
        return false;
    }

    // Reference nodes: an identifier or a member/scoped expression whose exact
    // source text matches a registered UserInputSource member.
    let is_ref = spec.map_or(
        matches!(
            kind,
            "identifier"
                | "member_expression"
                | "scoped_identifier"
                | "subscript_expression"
                | "field_identifier"
                | "property_identifier"
        ),
        |s| {
            matches!(
                s.classify(kind),
                NodeRole::Identifier | NodeRole::MemberAccess { .. }
            )
        },
    );

    if is_ref {
        let text = &source[node.start_byte()..node.end_byte()];
        if let Some(&motif) = lookup.get(text) {
            if motif == "UserInputSource" {
                return true;
            }
        }
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if rhs_references_source(cursor.node(), source, lookup, spec) {
                return true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    false
}

/// Returns true if any argument subtree references `name` as an identifier
/// (or member-object) node, ignoring string literal content.
fn args_reference_var(node: Node<'_>, source: &str, name: &str) -> bool {
    let kind = node.kind();

    // Never treat literal text as a reference.
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
        return false;
    }

    if kind == "identifier" {
        return &source[node.start_byte()..node.end_byte()] == name;
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if args_reference_var(cursor.node(), source, name) {
                return true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    false
}

fn find_sink_paths(
    node: Node<'_>,
    source: &str,
    tainted: &FxHashMap<String, &'static str>,
    lookup: &FxHashMap<String, &'static str>,
    import_map: Option<&crate::import_resolver::ImportMap>,
    spec: Option<&dyn LanguageSpec>,
    out: &mut FxHashSet<u64>,
) {
    let is_call = spec.map_or(node.kind() == "call_expression", |s| {
        matches!(s.classify(node.kind()), NodeRole::Call { .. })
    });

    if is_call {
        let callee_field = spec.and_then(|s| match s.classify(node.kind()) {
            NodeRole::Call { callee_field, .. } => Some(callee_field),
            _ => None,
        });
        if let Some(func) = node.child_by_field_name(callee_field.unwrap_or("function")) {
            let call_name = &source[func.start_byte()..func.end_byte()];
            // Resolve to motif
            let mut sink_motif = lookup.get(call_name).copied().or_else(|| {
                call_name
                    .rfind("::")
                    .or_else(|| call_name.rfind('.'))
                    .and_then(|p| lookup.get(&call_name[p + 1..]).copied())
            });

            // Fallback: check if the receiver comes from a known package sink category
            if sink_motif.is_none() {
                if let Some(imap) = import_map {
                    if let Some(receiver) = call_name.split('.').next() {
                        if let Some(pkg) = imap.resolve(receiver) {
                            if let Some(cat) =
                                crate::semantic::package_sink_category_from_spec(pkg, spec)
                            {
                                sink_motif = match cat {
                                    crate::corpus::source_sink::SinkCategory::SqlInjection => {
                                        Some("SqlSink")
                                    }
                                    crate::corpus::source_sink::SinkCategory::NoSqlInjection => {
                                        Some("NoSqlSink")
                                    }
                                    crate::corpus::source_sink::SinkCategory::CommandInjection => {
                                        Some("CommandExecutionSink")
                                    }
                                    crate::corpus::source_sink::SinkCategory::Ssrf => {
                                        Some("SsrfSink")
                                    }
                                    crate::corpus::source_sink::SinkCategory::PathTraversal => {
                                        Some("FsSink")
                                    }
                                    _ => None,
                                };
                            }
                        }
                    }
                }
            }

            if let Some(sink_motif) = sink_motif {
                // Check arguments for tainted variables by AST reference, not
                // substring. A sink called with a string literal that merely
                // happens to contain a variable name must not mint a path hash.
                if let Some(args) = node.child_by_field_name("arguments") {
                    for (var, &source_motif) in tainted {
                        if args_reference_var(args, source, var) {
                            // Emit path: source_motif → sink_motif
                            let path = FlowPath {
                                labels: vec![source_motif, "taint_flow", sink_motif],
                            };
                            out.insert(path.hash());
                        }
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            find_sink_paths(
                cursor.node(),
                source,
                tainted,
                lookup,
                import_map,
                spec,
                out,
            );
            if !cursor.goto_next_sibling() {
                break;
            }
        }
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

    fn tainted_vars(code: &str) -> FxHashMap<String, &'static str> {
        let tree = parse_ts(code);
        let lookup = &*crate::corpus::motifs::MOTIF_LOOKUP;
        collect_tainted_vars(tree.root_node(), code, lookup, None, None)
    }

    #[test]
    fn source_member_in_string_literal_is_not_tainted() {
        let code = r#"
function logRequest() {
    let logMsg = "Processing req.body data for audit";
    console.log(logMsg);
}
"#;
        let tainted = tainted_vars(code);
        assert!(
            tainted.is_empty(),
            "string literals must not taint variables, got {tainted:?}"
        );
    }

    #[test]
    fn genuine_member_reference_is_tainted() {
        let code = r#"
function handler() {
    let cmd = req.body.command;
    console.log(cmd);
}
"#;
        let tainted = tainted_vars(code);
        assert_eq!(tainted.get("cmd"), Some(&"UserInputSource"));
    }

    #[test]
    fn plain_member_access_on_source_is_tainted() {
        let code = r#"
function handler() {
    let q = req.query;
    use(q);
}
"#;
        let tainted = tainted_vars(code);
        assert_eq!(tainted.get("q"), Some(&"UserInputSource"));
    }

    #[test]
    fn sink_call_with_var_name_in_string_literal_gets_no_flow_path() {
        let code = "function handler() { let cmd = req.body.command; exec(\"cmd was executed\"); }";
        let tree = parse_ts(code);
        let lookup = &*crate::corpus::motifs::MOTIF_LOOKUP;
        let tainted = collect_tainted_vars(tree.root_node(), code, lookup, None, None);
        assert_eq!(tainted.get("cmd"), Some(&"UserInputSource"));
        let mut hashes = FxHashSet::default();
        find_sink_paths(
            tree.root_node(),
            code,
            &tainted,
            lookup,
            None,
            None,
            &mut hashes,
        );
        assert!(
            hashes.is_empty(),
            "string-literal arg must not produce a flow path, got {hashes:?}"
        );
    }

    #[test]
    fn sink_call_with_real_var_reference_emits_flow_path() {
        let code = "function handler() { let cmd = req.body.command; exec(cmd); }";
        let tree = parse_ts(code);
        let lookup = &*crate::corpus::motifs::MOTIF_LOOKUP;
        let tainted = collect_tainted_vars(tree.root_node(), code, lookup, None, None);
        let mut hashes = FxHashSet::default();
        find_sink_paths(
            tree.root_node(),
            code,
            &tainted,
            lookup,
            None,
            None,
            &mut hashes,
        );
        assert_eq!(
            hashes.len(),
            1,
            "genuine flow should emit one path, got {hashes:?}"
        );
    }

    #[test]
    fn template_substitution_reference_is_tainted() {
        let code = r#"
function handler() {
    let msg = `value: ${req.body.field}`;
    send(msg);
}
"#;
        let tainted = tainted_vars(code);
        assert_eq!(tainted.get("msg"), Some(&"UserInputSource"));
    }
}
