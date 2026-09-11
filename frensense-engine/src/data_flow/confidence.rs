// SPDX-License-Identifier: MIT

use std::path::Path;

use crate::cfg::build_cfg;
use crate::cfg::def_use::compute_def_use;
use crate::corpus::source_sink::CorpusSourceSinkRegistry;
use frensense_lang::spec::NodeRole;
use frensense_lang::spec_for_ext;

/// Maximum number of definition hops we trace backward before giving up.
/// Beyond this the value is treated as unresolvable.
const MAX_HOPS: usize = 3;

// ─────────────────────────────────────────────────────────────────────────────
// Confidence-adjustment constants
//
// The graduated multiplier table and the output floor below shape how taint
// confidence survives the def-use unwind. They are named and documented here so
// a single wrong value cannot silently crush (or inflate) confidence across the
// whole pipeline.
// ─────────────────────────────────────────────────────────────────────────────

/// Floor for adjusted confidence: the result of `adjust_confidence` is never
/// pushed below this, even when no real source can be confirmed. Prevents a
/// hard cliff-edge cut that would bury otherwise-plausible findings.
const CONFIDENCE_ADJUSTER_FLOOR: f32 = 0.35;

/// Graduated multipliers by def-hop distance to a confirmed source:
/// direct def is a confirmed source — no penalty.
const DIRECT_SOURCE_MULTIPLIER: f32 = 1.0;
/// One intermediate def hop to a confirmed source.
const ONE_HOP_MULTIPLIER: f32 = 0.8;
/// Two intermediate def hops to a confirmed source.
const TWO_HOP_MULTIPLIER: f32 = 0.75;
/// Three or more def hops to a confirmed source.
const THREE_PLUS_HOP_MULTIPLIER: f32 = 0.7;
/// No real source confirmed within `MAX_HOPS` — unresolvable.
const UNRESOLVABLE_MULTIPLIER: f32 = 0.6;

/// Byte window around a sink use within which a reaching def must fall.
const SINK_USE_WINDOW_BYTES: usize = 200;

/// Byte padding before a def when slicing source context for source detection.
const SOURCE_CONTEXT_PREFIX_BYTES: usize = 5;
/// Byte padding after a def when slicing source context for source detection.
const SOURCE_CONTEXT_SUFFIX_BYTES: usize = 40;

pub struct TaintConfidenceAdjuster;

impl TaintConfidenceAdjuster {
    pub fn adjust_confidence(
        source: &str,
        file_path: &Path,
        sink_line: u32,
        _sink_content: &str,
        original_confidence: f32,
        registry: &CorpusSourceSinkRegistry,
        local_tainted_vars: Option<&[String]>,
    ) -> f32 {
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let lang_name = crate::parser::ext_to_language(ext);
        if lang_name == "unknown" {
            println!("lang_name is unknown");
            return original_confidence;
        }

        let mut parser = tree_sitter::Parser::new();
        let lang = crate::parser::ParserRegistry::get_language_by_name(lang_name);
        let Ok(lang) = lang else {
            println!("get_language failed");
            return original_confidence;
        };
        if parser.set_language(&lang).is_err() {
            println!("set_language failed");
            return original_confidence;
        }
        let Some(tree) = parser.parse(source, None) else {
            println!("parse failed");
            return original_confidence;
        };
        let root = tree.root_node();
        let spec = spec_for_ext(ext);

        let cfg = build_cfg(root, source, ext);
        let def_use = compute_def_use(&cfg, source, spec_for_ext(ext));

        let sink_byte = find_line_byte(source, sink_line);

        let var_name = extract_sink_var_from_ast(root, source, sink_byte, spec);
        if var_name.is_empty() {
            println!("var_name is empty for sink_byte {}", sink_byte);
            return original_confidence;
        }

        let candidates: Vec<usize> = def_use
            .uses
            .iter()
            .enumerate()
            .filter(|(_, u)| {
                u.name == var_name
                    && sink_byte > 0
                    && u.start_byte <= sink_byte + SINK_USE_WINDOW_BYTES
                    && u.end_byte >= sink_byte.saturating_sub(SINK_USE_WINDOW_BYTES)
            })
            .map(|(i, _)| i)
            .collect();

        if candidates.is_empty() {
            println!("candidates is empty, var_name={}", var_name);
            return original_confidence;
        }

        // Unwind the smallest number of def hops back to a real source. The
        // result is a graduated confidence multiplier instead of a single
        // cliff-edge cut: the fewer hops to a confirmed source, the higher the
        // retained confidence. Values that never reach a source are downgraded
        // to a floor multiplier rather than crushed to 35%.
        let mut min_hops: Option<usize> = None;
        for &use_idx in &candidates {
            if let Some(hops) = trace_hops_to_source(
                &def_use,
                use_idx,
                source,
                root,
                registry,
                local_tainted_vars,
                0,
                spec,
            ) {
                min_hops = Some(min_hops.map_or(hops, |m| m.min(hops)));
            }
        }

        let multiplier = match min_hops {
            Some(0) => DIRECT_SOURCE_MULTIPLIER, // direct def is a confirmed source — no penalty
            Some(1) => ONE_HOP_MULTIPLIER,
            Some(2) => TWO_HOP_MULTIPLIER,
            Some(_) => THREE_PLUS_HOP_MULTIPLIER,
            None => UNRESOLVABLE_MULTIPLIER, // unresolvable — could not confirm any real source
        };

        (original_confidence * multiplier).max(CONFIDENCE_ADJUSTER_FLOOR)
    }
}

/// Recursively unwind the reaching definitions of `use_idx`. Returns the depth
/// at which a confirmed real source is first encountered, or `None` if no
/// source can be reached within `MAX_HOPS`.
#[allow(clippy::too_many_arguments)]
fn trace_hops_to_source(
    def_use: &crate::cfg::def_use::DefUseChain,
    use_idx: usize,
    source: &str,
    root: tree_sitter::Node,
    registry: &CorpusSourceSinkRegistry,
    local_tainted_vars: Option<&[String]>,
    depth: usize,
    spec: Option<&dyn frensense_lang::spec::LanguageSpec>,
) -> Option<usize> {
    if depth > MAX_HOPS {
        return None;
    }

    // Check all definitions that reach this use.
    for def in def_use.defs_reaching(use_idx) {
        if is_real_source(def, source, root, registry, local_tainted_vars, spec) {
            return Some(depth);
        }
        // This def derives from an RHS expression referencing other variable(s)
        // (e.g. `let data = sanitize(raw)`). The def's own span is just the
        // bound name, so the references it depends on live in the same block,
        // immediately after the def, within a bounded window. Follow those
        // references a level deeper to unwind the chain.
        for (rhs_use_idx, rhs_use) in def_use.uses.iter().enumerate() {
            if rhs_use.block_id == def.block_id
                && rhs_use.name != def.name
                && rhs_use.start_byte >= def.start_byte
                && rhs_use.end_byte <= def.end_byte + SINK_USE_WINDOW_BYTES
            {
                if let Some(hops) = trace_hops_to_source(
                    def_use,
                    rhs_use_idx,
                    source,
                    root,
                    registry,
                    local_tainted_vars,
                    depth + 1,
                    spec,
                ) {
                    return Some(hops);
                }
            }
        }
    }
    None
}

fn extract_sink_var_from_ast(
    root: tree_sitter::Node,
    source: &str,
    sink_byte: usize,
    spec: Option<&dyn frensense_lang::spec::LanguageSpec>,
) -> String {
    // Find the call expression at or near sink_byte
    if let Some(call_node) = root.descendant_for_byte_range(sink_byte, sink_byte + 10) {
        let mut cur = call_node;
        loop {
            let is_call = spec.map_or(false, |s| {
                matches!(s.classify(cur.kind()), NodeRole::Call { .. })
            }) || cur.kind() == "call_expression";
            if is_call {
                // Get the first argument
                if let Some(args) = cur.child_by_field_name("arguments") {
                    let mut c = args.walk();
                    if c.goto_first_child() {
                        loop {
                            let child = c.node();
                            if matches!(
                                child.kind(),
                                "identifier" | "member_expression" | "field_expression"
                            ) {
                                return source[child.start_byte()..child.end_byte()].to_string();
                            }
                            if !c.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
                break;
            }
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
    }
    String::new()
}

fn find_line_byte(source: &str, target_line: u32) -> usize {
    let mut line = 1u32;
    for (i, &b) in source.as_bytes().iter().enumerate() {
        if line == target_line {
            let mut j = i;
            let bytes = source.as_bytes();
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            return j;
        }
        if b == b'\n' {
            line += 1;
        }
    }
    source.len()
}

fn is_real_source(
    def: &crate::cfg::def_use::Definition,
    source: &str,
    root: tree_sitter::Node,
    registry: &CorpusSourceSinkRegistry,
    local_tainted_vars: Option<&[String]>,
    spec: Option<&dyn frensense_lang::spec::LanguageSpec>,
) -> bool {
    let mut start = def.start_byte.saturating_sub(SOURCE_CONTEXT_PREFIX_BYTES);
    while start > 0 && !source.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (def.end_byte + SOURCE_CONTEXT_SUFFIX_BYTES).min(source.len());
    while end < source.len() && !source.is_char_boundary(end) {
        end += 1;
    }
    let context = &source[start..end];

    if registry.is_source_pattern(context) {
        return true;
    }

    if let Some(local_vars) = local_tainted_vars {
        if local_vars.contains(&def.name) {
            return true;
        }
    }

    if let Some(type_name) = resolve_declared_type(def, root, source, spec) {
        return registry.is_source_type(&type_name);
    }

    false
}

fn resolve_declared_type(
    def: &crate::cfg::def_use::Definition,
    root: tree_sitter::Node,
    source: &str,
    spec: Option<&dyn frensense_lang::spec::LanguageSpec>,
) -> Option<String> {
    let node = root.descendant_for_byte_range(def.start_byte, def.end_byte)?;

    let mut current = node;
    loop {
        match current.kind() {
            "variable_declarator"
            | "required_parameter"
            | "optional_parameter"
            | "parameter"
            | "identifier" => {
                let mut cursor = current.walk();
                for child in current.children(&mut cursor) {
                    match child.kind() {
                        "type_annotation"
                        | "type_identifier"
                        | "scoped_type_identifier"
                        | "generic_type" => {
                            let ty = source[child.start_byte()..child.end_byte()].trim();
                            if !ty.is_empty() {
                                let clean = ty.trim_start_matches(':').trim();
                                return Some(clean.to_string());
                            }
                        }
                        _ => {}
                    }
                }
                if matches!(
                    current.kind(),
                    "variable_declarator"
                        | "required_parameter"
                        | "optional_parameter"
                        | "parameter"
                ) {
                    break;
                }
            }
            "assignment_expression" | "assignment" | "expression_statement" => break,
            kind if spec.map_or(false, |s| s.is_function_node(kind))
                || matches!(
                    kind,
                    "function_definition"
                        | "function_declaration"
                        | "arrow_function"
                        | "method_definition"
                        | "function_item"
                ) =>
            {
                break;
            }
            _ => {}
        }
        if let Some(parent) = current.parent() {
            current = parent;
        } else {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_reduces_confidence() {
        let source = r#"
fn reassign() {
    let data = get_password();
    data = "clean";
    store_in_db(data);
}
"#;
        let registry = CorpusSourceSinkRegistry::default();
        let confidence = TaintConfidenceAdjuster::adjust_confidence(
            source,
            Path::new("test.rs"),
            5,
            "store_in_db(data)",
            0.95,
            &registry,
            None,
        );
        assert!(
            confidence < 0.95,
            "reassignment should reduce confidence, got {confidence}"
        );
    }

    #[test]
    fn test_no_kill_preserves_confidence() {
        let source = r"
fn no_kill() {
    let data = req.query.id;
    store_in_db(data);
}
";
        let registry = CorpusSourceSinkRegistry::default();
        let confidence = TaintConfidenceAdjuster::adjust_confidence(
            source,
            Path::new("test.rs"),
            4,
            "store_in_db(data)",
            0.95,
            &registry,
            None,
        );
        assert!(
            confidence > 0.80,
            "direct flow should preserve high confidence, got {confidence}"
        );
    }

    #[test]
    fn test_hardcoded_constant_not_source() {
        // Here `input` is just a hardcoded string, but under the old logic
        // `matches_source_name` would see `input` and think it's a source.
        // It shouldn't be treated as a real source anymore.
        let source = r#"
fn test_constant() {
    let input = "hardcoded_constant";
    store_in_db(input);
}
"#;
        let registry = CorpusSourceSinkRegistry::default();
        let confidence = TaintConfidenceAdjuster::adjust_confidence(
            source,
            Path::new("test.rs"),
            4,
            "store_in_db(input)",
            0.95,
            &registry,
            None,
        );
        // Because it's not a real source, confidence should drop
        assert!(
            confidence < 0.95,
            "hardcoded constant in 'input' should reduce confidence, got {confidence}"
        );
    }

    #[test]
    fn test_unknown_language_returns_original() {
        let registry = CorpusSourceSinkRegistry::default();
        let confidence = TaintConfidenceAdjuster::adjust_confidence(
            "",
            Path::new("test.abc"),
            1,
            "",
            0.90,
            &registry,
            None,
        );
        assert!(
            (confidence - 0.90).abs() < f32::EPSILON,
            "unknown language should return original"
        );
    }

    #[test]
    fn test_indirect_source_retains_most_confidence() {
        // `data` reaches a confirmed source through one intermediate def hop
        // (`let data = sanitize(raw)` uses `raw`, which is a real source). The
        // graduated scale must keep this high (×0.75), far above the
        // unresolvable floor, and below a fully direct flow (×1.0).
        let source = r#"
fn transform() {
    let raw = req.body.username;
    let data = sanitize(raw);
    store_in_db(data);
}
"#;
        let registry = CorpusSourceSinkRegistry::default();
        let confidence = TaintConfidenceAdjuster::adjust_confidence(
            source,
            Path::new("test.rs"),
            5,
            "store_in_db(data)",
            0.95,
            &registry,
            None,
        );
        // 0.95 * 0.75 = 0.7125
        assert!(
            confidence > 0.60 && confidence < 0.85,
            "indirect source should be graduated (×0.75), got {confidence}"
        );
    }

    #[test]
    fn test_unresolvable_not_crushed_as_hard_as_before() {
        // No source can be confirmed: with the old logic this was cut to
        // 0.95 * 0.35 = 0.3325 → floored 0.15 path. Now it sits at the
        // graduated unresolvable multiplier ×0.6 = 0.57.
        let source = r#"
fn produce() {
    let intermediate = compute_thing();
    let data = refine(intermediate, 1);
    store_in_db(data);
}
"#;
        let registry = CorpusSourceSinkRegistry::default();
        let confidence = TaintConfidenceAdjuster::adjust_confidence(
            source,
            Path::new("test.rs"),
            5,
            "store_in_db(data)",
            0.95,
            &registry,
            None,
        );
        assert!(
            confidence > 0.45 && confidence < 0.65,
            "unresolvable should be ×0.6 ≈ 0.57, got {confidence}"
        );
    }
}
