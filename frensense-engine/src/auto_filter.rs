use crate::corpus::semantic::SemanticFilter;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoFilterStats {
    pub contains_call_to: HashMap<String, Vec<String>>,
    pub must_not_contain_call_to: HashMap<String, Vec<String>>,
    pub function_name_regex: HashMap<String, String>,
    pub contains_node_type: HashMap<String, Vec<String>>,
    pub must_not_contain_node_type: HashMap<String, Vec<String>>,
    pub must_not_match_function_name: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoFilterEntry {
    pub pattern_id: String,
    pub required_calls: HashSet<String>,
    pub forbidden_calls: HashSet<String>,
    pub required_node_types: HashSet<String>,
    pub forbidden_node_types: HashSet<String>,
    pub forbidden_fn_names: HashSet<String>,
}

fn strip_comments_and_strings(source: &str) -> String {
    // Basic implementation for extract_call_targets
    let mut out = String::with_capacity(source.len());
    let mut in_str = false;
    let mut str_char = '\0';
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let chars: Vec<char> = source.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
                out.push('\n');
            }
        } else if in_block_comment {
            if c == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                in_block_comment = false;
                i += 1;
            }
        } else if in_str {
            if c == '\\' {
                i += 1;
            } else if c == str_char {
                in_str = false;
                out.push(c);
            } else {
                out.push(c);
            }
        } else {
            if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
                in_line_comment = true;
                i += 1;
            } else if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
                in_block_comment = true;
                i += 1;
            } else if c == '"' || c == '\'' || c == '`' {
                in_str = true;
                str_char = c;
                out.push(c);
            } else {
                out.push(c);
            }
        }
        i += 1;
    }
    out
}

pub fn extract_call_targets(source: &str) -> HashSet<String> {
    let clean_source = strip_comments_and_strings(source);
    let mut targets = HashSet::new();
    let re = regex::Regex::new(r"([a-zA-Z0-9_]+)\s*\(").unwrap();
    for cap in re.captures_iter(&clean_source) {
        targets.insert(cap[1].to_string());
    }
    targets
}

pub fn merge_filters(
    manual: Option<&SemanticFilter>,
    auto: Option<&AutoFilterStats>,
    pattern_id: &str,
) -> SemanticFilter {
    let mut merged = manual.cloned().unwrap_or_default();

    if let Some(stats) = auto {
        if let Some(calls) = stats.contains_call_to.get(pattern_id) {
            for call in calls {
                if !merged.contains_call_to.contains(call) {
                    merged.contains_call_to.push(call.clone());
                }
            }
        }
        if let Some(excludes) = stats.must_not_contain_call_to.get(pattern_id) {
            for ex in excludes {
                if !merged.must_not_contain_call_to.contains(ex) {
                    merged.must_not_contain_call_to.push(ex.clone());
                }
            }
        }
        if let Some(req_nodes) = stats.contains_node_type.get(pattern_id) {
            for node in req_nodes {
                if !merged.contains_node_type.contains(node) {
                    merged.contains_node_type.push(node.clone());
                }
            }
        }
        if let Some(excludes) = stats.must_not_contain_node_type.get(pattern_id) {
            for ex in excludes {
                if !merged.must_not_contain_node_type.contains(ex) {
                    merged.must_not_contain_node_type.push(ex.clone());
                }
            }
        }
        if let Some(re) = stats.function_name_regex.get(pattern_id) {
            if merged.function_name_regex.is_none() {
                merged.function_name_regex = Some(re.clone());
            }
        }
        if let Some(nodes) = stats.must_not_contain_node_type.get(pattern_id) {
            for node in nodes {
                if !merged.must_not_contain_node_type.contains(node) {
                    merged.must_not_contain_node_type.push(node.clone());
                }
            }
        }
        if let Some(fnames) = stats.must_not_match_function_name.get(pattern_id) {
            for fname in fnames {
                if !merged.must_not_match_function_name.contains(fname) {
                    merged.must_not_match_function_name.push(fname.clone());
                }
            }
        }
    }
    merged
}
