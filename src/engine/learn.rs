// SPDX-License-Identifier: MIT

//! Pattern learning from corpus pairs.
//!
//! Given a positive (buggy) and negative (fixed) file:
//! 1. Copy them to a temp directory with proper naming
//! 2. Use AST diffing to extract what changed
//! 3. Generate pattern metadata from the diff
//! 4. Save as corpus files

use crate::engine::ast_diff::{PatternKind, diff_ast, extract_patterns_from_diff};
use std::path::Path;

///
/// # Panics
/// May panic if internal assertions fail.
/// Learn a pattern from a positive/negative pair.
/// Learn pattern.
///
/// # Errors
/// Returns an error if it fails.
pub fn learn_pattern(
    positive_path: &Path,
    negative_path: &Path,
    pattern_id: &str,
    output_dir: &Path,
) -> Result<LearnResult, String> {
    // Read source files for AST diffing
    let positive_source = std::fs::read_to_string(positive_path)
        .map_err(|e| format!("Failed to read {}: {}", positive_path.display(), e))?;
    let negative_source = std::fs::read_to_string(negative_path)
        .map_err(|e| format!("Failed to read {}: {}", negative_path.display(), e))?;

    // Perform AST diff
    let diff = diff_ast(
        &positive_source,
        &negative_source,
        &positive_path.to_string_lossy(),
        &negative_path.to_string_lossy(),
    )?;

    // Extract learned patterns from diff
    let learned_patterns = extract_patterns_from_diff(&diff);

    // Generate metadata from diff and positive source context
    let expected_context =
        frensense_engine::context::FileContext::extract(positive_path, &positive_source);
    let mut metadata = generate_metadata(&diff, &learned_patterns);
    metadata.expected_context = Some(expected_context);

    // Create output directory
    std::fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;

    // Copy files with proper naming convention
    let pos_ext = positive_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let neg_ext = negative_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let pos_name = format!("{pattern_id}_positive.{pos_ext}");
    let neg_name = format!("{pattern_id}_negative.{neg_ext}");

    let pos_dest = output_dir.join(&pos_name);
    let neg_dest = output_dir.join(&neg_name);

    std::fs::copy(positive_path, &pos_dest).map_err(|e| e.to_string())?;
    std::fs::copy(negative_path, &neg_dest).map_err(|e| e.to_string())?;

    // Write metadata file with semantic constraints and advisory text
    let metadata_path = output_dir.join(format!("{pattern_id}.toml"));
    let metadata_toml = generate_toml(pattern_id, &metadata, &learned_patterns, &diff);
    std::fs::write(&metadata_path, &metadata_toml).map_err(|e| e.to_string())?;

    // Load using the corpus loader to verify
    let (patterns, _warnings) = frensense_bundler::loader::load_corpus(output_dir)
        .map_err(|e| format!("Failed to load corpus: {e}"))?;

    let positive_fps: usize = patterns.iter().map(|p| p.positives.len()).sum();
    let negative_fps: usize = patterns.iter().map(|p| p.negatives.len()).sum();

    Ok(LearnResult {
        pattern_id: pattern_id.to_string(),
        positive_functions: positive_fps,
        negative_functions: negative_fps,
        positive_path: pos_dest,
        negative_path: neg_dest,
        metadata_path,
        diff_summary: generate_diff_summary(&diff),
        learned_patterns,
    })
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Generate metadata from AST diff.
fn generate_metadata(
    diff: &crate::engine::ast_diff::AstDiff,
    patterns: &[LearnedPattern],
) -> PatternMetadata {
    let mut metadata = PatternMetadata {
        bug_type: "unknown".to_string(),
        sanitizer: None,
        source_pattern: None,
        sink_pattern: None,
        confidence: 0.5,
        expected_context: None,
    };

    // Analyze patterns to determine bug type
    for pattern in patterns {
        match pattern.kind {
            PatternKind::Sanitizer => {
                metadata.sanitizer = Some(pattern.description.clone());
                metadata.confidence = 0.8;
            }
            PatternKind::BugPattern => {
                metadata.sink_pattern = Some(pattern.description.clone());
            }
            PatternKind::CallChange => {}
        }
    }

    // Determine bug type from changes
    if !diff.modified_functions.is_empty() {
        let func = &diff.modified_functions[0];
        for change in &func.changes {
            match change.kind {
                crate::engine::ast_diff::ChangeKind::CallAdded
                    if (change.description.contains("sanitize")
                        || change.description.contains("validate")
                        || change.description.contains("check")) =>
                {
                    metadata.bug_type = "missing_sanitization".to_string();
                }
                crate::engine::ast_diff::ChangeKind::CallRemoved
                    if (change.description.contains("eval")
                        || change.description.contains("exec")
                        || change.description.contains("system")) =>
                {
                    metadata.bug_type = "dangerous_function_call".to_string();
                }
                crate::engine::ast_diff::ChangeKind::CallAdded
                | crate::engine::ast_diff::ChangeKind::CallRemoved
                | crate::engine::ast_diff::ChangeKind::AssignmentChanged
                | crate::engine::ast_diff::ChangeKind::ConditionalChanged => {}
            }
        }
    }

    metadata
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Generate TOML metadata file with semantic constraints and advisory text.
fn generate_toml(
    pattern_id: &str,
    metadata: &PatternMetadata,
    patterns: &[LearnedPattern],
    diff: &crate::engine::ast_diff::AstDiff,
) -> String {
    use std::fmt::Write;
    let mut toml = String::new();
    let _ = writeln!(toml, "# Auto-generated metadata for pattern: {pattern_id}");
    let _ = writeln!(toml, "# Generated by: frensense --learn");
    let _ = writeln!(toml, "# Positive (buggy): {pattern_id}_positive");
    let _ = writeln!(toml, "# Negative (fixed): {pattern_id}_negative\n");

    // Core metadata
    let _ = writeln!(toml, "id = \"{}\"", pattern_id.to_uppercase());
    let _ = writeln!(toml, "bug_type = \"{}\"", metadata.bug_type);
    let _ = writeln!(toml, "confidence = {}\n", metadata.confidence);

    if let Some(ctx) = &metadata.expected_context {
        let _ = writeln!(toml, "# Automatically inferred context from positive file");
        let _ = writeln!(toml, "[expected_context]");
        let _ = writeln!(toml, "environment = \"{:?}\"", ctx.environment);
        let _ = writeln!(toml, "sensitivity = \"{:?}\"", ctx.sensitivity);
        if !ctx.frameworks.is_empty() {
            let _ = writeln!(toml, "frameworks = {:?}", ctx.frameworks);
        }
        let _ = writeln!(toml, "");
    }

    // Advisory text (auto-generated from diff analysis)
    let _ = writeln!(toml, "# Advisory text - what to tell the developer");
    let (observation, impact, improvement) = generate_advisory_text(pattern_id, metadata, diff);
    let _ = writeln!(toml, "observation = \"{observation}\"");
    let _ = writeln!(toml, "impact = \"{impact}\"");
    let _ = writeln!(toml, "improvement = \"{improvement}\"\n");

    // Semantic constraints (auto-generated from diff)
    let _ = writeln!(
        toml,
        "# Semantic constraints - what AST features must be present"
    );
    let constraints = generate_semantic_constraints(metadata, diff);
    if !constraints.required_calls.is_empty() {
        let _ = writeln!(toml, "contains_call_to = {:?}", constraints.required_calls);
    }
    if !constraints.forbidden_calls.is_empty() {
        let _ = writeln!(
            toml,
            "must_not_contain_call_to = {:?}",
            constraints.forbidden_calls
        );
    }
    if !constraints.required_node_types.is_empty() {
        let _ = writeln!(
            toml,
            "contains_node_type = {:?}",
            constraints.required_node_types
        );
    }
    if !constraints.forbidden_node_types.is_empty() {
        let _ = writeln!(
            toml,
            "must_not_contain_node_type = {:?}",
            constraints.forbidden_node_types
        );
    }

    // Taint rule (auto-generated if applicable)
    if metadata.bug_type == "missing_sanitization" || metadata.bug_type == "dangerous_function_call"
    {
        let _ = writeln!(toml, "\n# Auto-generated taint rule");
        let _ = writeln!(toml, "[[taint_rule]]");
        let _ = writeln!(toml, "id = \"TAINT_{}\"", pattern_id.to_uppercase());
        let _ = writeln!(
            toml,
            "source = \"req\\.body|req\\.query|input|user|params\""
        );
        let _ = writeln!(
            toml,
            "sink = \"{}\"",
            metadata.sink_pattern.as_deref().unwrap_or("eval|exec")
        );
        let _ = writeln!(toml, "severity = \"warning\"");
        let _ = writeln!(toml, "observation = \"{observation}\"");
        let _ = writeln!(toml, "improvement = \"{improvement}\"");
    }

    // Learned patterns from AST diff
    if !patterns.is_empty() {
        let _ = writeln!(toml, "\n# Patterns learned from AST diff");
        for pattern in patterns {
            let _ = writeln!(toml, "\n[[learned]]");
            let _ = writeln!(toml, "kind = \"{:?}\"", pattern.kind);
            let _ = writeln!(toml, "function = \"{}\"", pattern.function);
            let _ = writeln!(toml, "description = \"{}\"", pattern.description);
        }
    }

    toml
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Auto-generated advisory text from diff analysis.
fn generate_advisory_text(
    _pattern_id: &str,
    metadata: &PatternMetadata,
    diff: &crate::engine::ast_diff::AstDiff,
) -> (String, String, String) {
    let bug_type_desc = match metadata.bug_type.as_str() {
        "missing_sanitization" => "input is not sanitized before use",
        "dangerous_function_call" => "dangerous function is called with untrusted data",
        "timing_vulnerable" => "comparison uses non-constant-time operation",
        _ => "code pattern matches a known vulnerability",
    };

    // Observation: what the bug looks like
    let observation = if let Some(ref sink) = metadata.sink_pattern {
        format!("Function calls {sink} which can be exploited")
    } else if !diff.call_diffs.is_empty() {
        let removed: Vec<&str> = diff
            .call_diffs
            .iter()
            .filter_map(|c| c.callee_negative.as_deref())
            .collect();
        if removed.is_empty() {
            format!("Bug type: {bug_type_desc}")
        } else {
            format!("Missing safety check: {} not called", removed.join(", "))
        }
    } else {
        format!("Bug type: {bug_type_desc}")
    };

    // Impact: what goes wrong
    let impact = match metadata.bug_type.as_str() {
        "missing_sanitization" => "Untrusted input flows to sensitive operation without validation",
        "dangerous_function_call" => "Attacker-controlled data reaches dangerous function",
        "timing_vulnerable" => "Timing side-channel allows secret recovery",
        _ => "Code pattern matches a known vulnerability class",
    }
    .to_string();

    // Improvement: how to fix it
    let improvement = if let Some(ref sanitizer) = metadata.sanitizer {
        format!("Apply {sanitizer} before using the value")
    } else if let Some(ref sink) = metadata.sink_pattern {
        format!("Validate and sanitize input before calling {sink}")
    } else {
        match metadata.bug_type.as_str() {
            "missing_sanitization" => "Add input validation and sanitization",
            "dangerous_function_call" => "Use safe alternatives or validate input",
            "timing_vulnerable" => "Use constant-time comparison (e.g., crypto.timingSafeEqual)",
            _ => "Review against corpus example and apply fix",
        }
        .to_string()
    };

    (observation, impact, improvement)
}

/// Auto-generated semantic constraints from diff analysis.
struct SemanticConstraints {
    required_calls: Vec<String>,
    forbidden_calls: Vec<String>,
    required_node_types: Vec<String>,
    forbidden_node_types: Vec<String>,
}

fn generate_semantic_constraints(
    metadata: &PatternMetadata,
    diff: &crate::engine::ast_diff::AstDiff,
) -> SemanticConstraints {
    let mut required_calls = Vec::new();
    let mut forbidden_calls = Vec::new();

    // Analyze call changes to determine required/forbidden calls
    for func in &diff.modified_functions {
        for change in &func.changes {
            match change.kind {
                crate::engine::ast_diff::ChangeKind::CallRemoved => {
                    // Call removed in negative = this call is the bug marker
                    // Extract the call target from description
                    if let Some(target) = extract_call_target(&change.description) {
                        required_calls.push(target);
                    }
                }
                crate::engine::ast_diff::ChangeKind::CallAdded => {
                    // Call added in negative = this is the fix
                    // Extract the call target from description
                    if let Some(target) = extract_call_target(&change.description) {
                        forbidden_calls.push(target);
                    }
                }
                crate::engine::ast_diff::ChangeKind::AssignmentChanged
                | crate::engine::ast_diff::ChangeKind::ConditionalChanged => {}
            }
        }
    }

    // Add sink pattern as required call if available
    if let Some(ref sink) = metadata.sink_pattern {
        for call in sink.split('|') {
            let call = call.trim().to_string();
            if !call.is_empty() && !required_calls.contains(&call) {
                required_calls.push(call);
            }
        }
    }

    // Deduplicate
    required_calls.sort();
    required_calls.dedup();
    forbidden_calls.sort();
    forbidden_calls.dedup();

    SemanticConstraints {
        required_calls,
        forbidden_calls,
        required_node_types: Vec::new(), // Could be enhanced with more AST analysis
        forbidden_node_types: Vec::new(),
    }
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Extract call target from change description like "call to `eval()`".
fn extract_call_target(description: &str) -> Option<String> {
    // Look for patterns like "call to foo()" or "foo() called"
    if let Some(start) = description.find("call to ") {
        let rest = &description[start + 8..];
        if let Some(end) = rest.find('(') {
            return Some(rest[..end].to_string());
        }
    }
    if let Some(start) = description.find("()") {
        // Find the function name before ()
        let before = &description[..start];
        if let Some(name_start) = before.rfind(|c: char| c.is_whitespace() || c == '.' || c == ':')
        {
            return Some(before[name_start + 1..].to_string());
        }
    }
    None
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Generate a human-readable diff summary.
fn generate_diff_summary(diff: &crate::engine::ast_diff::AstDiff) -> String {
    use std::fmt::Write;
    let mut summary = String::new();

    if diff.modified_functions.is_empty() {
        let _ = writeln!(summary, "No function modifications detected.");
    } else {
        let _ = writeln!(
            summary,
            "{} function(s) modified:",
            diff.modified_functions.len()
        );
        for func in &diff.modified_functions {
            let _ = writeln!(
                summary,
                "  - {} (line {} → {}): {} change(s)",
                func.name,
                func.positive_line,
                func.negative_line,
                func.changes.len()
            );
            for change in &func.changes {
                let _ = writeln!(summary, "    • {}: {}", change.kind, change.description);
            }
        }
    }

    if !diff.call_diffs.is_empty() {
        let _ = writeln!(
            summary,
            "\n{} call graph difference(s):",
            diff.call_diffs.len()
        );
        for call in &diff.call_diffs {
            let _ = writeln!(
                summary,
                "  - {} → {:?} → {:?}",
                call.caller, call.callee_positive, call.callee_negative
            );
        }
    }

    summary
}

#[derive(Debug)]
pub struct LearnResult {
    pub pattern_id: String,
    pub positive_functions: usize,
    pub negative_functions: usize,
    pub positive_path: std::path::PathBuf,
    pub negative_path: std::path::PathBuf,
    pub metadata_path: std::path::PathBuf,
    pub diff_summary: String,
    pub learned_patterns: Vec<LearnedPattern>,
}

#[derive(Debug, Clone)]
pub struct PatternMetadata {
    pub bug_type: String,
    pub sanitizer: Option<String>,
    pub source_pattern: Option<String>,
    pub sink_pattern: Option<String>,
    pub confidence: f64,
    pub expected_context: Option<frensense_engine::context::FileContext>,
}

pub use crate::engine::ast_diff::LearnedPattern;

/// Load learned taint rules from a TOML file.
#[must_use]
pub fn load_learned_taint_rules(path: &std::path::Path) -> Vec<LearnedTaintRule> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    let Ok(doc) = content.parse::<toml::Table>() else {
        return Vec::new();
    };

    let mut result = Vec::new();

    // Handle single table: taint_rule = { ... }
    if let Some(rule) = doc.get("taint_rule").and_then(|r| r.as_table())
        && let Some(id) = rule.get("id").and_then(|v| v.as_str())
    {
        result.push(LearnedTaintRule {
            id: id.to_string(),
            source: rule
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sink: rule
                .get("sink")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            severity: rule
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("warning")
                .to_string(),
            observation: rule
                .get("observation")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            improvement: rule
                .get("improvement")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        });
    }

    // Handle array of tables: [[taint_rule]]
    if let Some(rules) = doc.get("taint_rule").and_then(|r| r.as_array()) {
        for rule in rules {
            if let Some(rule_table) = rule.as_table()
                && let Some(id) = rule_table.get("id").and_then(|v| v.as_str())
            {
                result.push(LearnedTaintRule {
                    id: id.to_string(),
                    source: rule_table
                        .get("source")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    sink: rule_table
                        .get("sink")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    severity: rule_table
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("warning")
                        .to_string(),
                    observation: rule_table
                        .get("observation")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    improvement: rule_table
                        .get("improvement")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
    }

    result
}

#[derive(Debug, Clone)]
pub struct LearnedTaintRule {
    pub id: String,
    pub source: String,
    pub sink: String,
    pub severity: String,
    pub observation: String,
    pub improvement: String,
}

impl LearnedTaintRule {
    /// Convert to TOML format for use with --extra-taint-rules.
    #[must_use]
    pub fn to_toml(&self) -> String {
        format!(
            r#"[[rules]]
id = "{}"
source = "{}"
sink = "{}"
severity = "{}"
observation = "{}"
improvement = "{}"
"#,
            self.id, self.source, self.sink, self.severity, self.observation, self.improvement
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_taint_rules() {
        let content = "[[taint_rule]]\nid = \"TAINT_TEST\"\nsource = \"req.body\"\nsink = \"eval\"\nseverity = \"warning\"\nobservation = \"Test\"\nimprovement = \"Test\"";

        // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let temp_dir = std::env::temp_dir().join("frensense_test_taint");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let path = temp_dir.join("test.toml");
        std::fs::write(&path, content).unwrap();

        let rules = load_learned_taint_rules(&path);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "TAINT_TEST");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_learn_pattern() {
        let positive =
            "function handler(req) {\n    const input = req.body.query;\n    eval(input);\n}";
        let negative = "function handler(req) {\n    const input = req.body.query;\n    const clean = sanitize(input);\n    eval(clean);\n}";

        // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let temp_dir = std::env::temp_dir().join("frensense_test_learn");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let pos_file = temp_dir.join("test_positive.ts");
        let neg_file = temp_dir.join("test_negative.ts");
        std::fs::write(&pos_file, positive).unwrap();
        std::fs::write(&neg_file, negative).unwrap();

        let result = learn_pattern(&pos_file, &neg_file, "test_pattern", &temp_dir);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.pattern_id, "test_pattern");
        assert!(!result.diff_summary.is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
