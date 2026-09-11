use super::options::CliOptions;
use crate::reporter::Reporter;
use crate::{Advisory, Engine, FrensenseError, Result};
use frensense_engine::pattern::evidence::MatchEvidence;
use std::collections::HashSet;
use std::path::Path;

/// Format a MatchEvidence as a human-readable block for the CLI reporter.
pub fn format_evidence(ev: &MatchEvidence) -> String {
    let mut lines = Vec::new();

    lines.push("  Matched:".to_string());
    for call in &ev.matched_calls {
        lines.push(format!("    v {}()", call));
    }
    for motif in &ev.matched_motifs {
        lines.push(format!("    v {} motif", motif));
    }
    if ev.has_taint_path {
        lines.push("    v user-input -> sink taint path".to_string());
    }
    if ev.control_flow_sim > 0.5 {
        lines.push(format!(
            "    v control flow ({:.0}% match)",
            ev.control_flow_sim * 100.0
        ));
    }
    if ev.ast_sim > 0.7 {
        lines.push(format!(
            "    v AST structure ({:.0}% match)",
            ev.ast_sim * 100.0
        ));
    }

    if !ev.missing_calls.is_empty() || ev.negative_sim > 0.4 {
        lines.push("  Differed:".to_string());
        for call in &ev.missing_calls {
            lines.push(format!("    x {} not found", call));
        }
        if ev.negative_sim > 0.4 {
            lines.push(format!(
                "    x {:.0}% similar to safe (negative) example",
                ev.negative_sim * 100.0
            ));
        }
    }

    lines.join("\n")
}

/// Print the results of the analysis in the requested format.
///
/// # Errors
/// Returns an error if the output cannot be serialized or written.
pub fn print_results(
    filtered_advisories: &[Advisory],
    format: &str,
    input_path: &Path,
) -> Result<()> {
    match format {
        "json" => {
            let clean = filtered_advisories.is_empty();
            let advisory_count = filtered_advisories.len();
            let requires_human_count = filtered_advisories
                .iter()
                .filter(|a| a.requires_human)
                .count();
            let auto_fixable_count = filtered_advisories
                .iter()
                .filter(|a| a.auto_fixable)
                .count();

            let wrapper = serde_json::json!({
                "clean": clean,
                "advisory_count": advisory_count,
                "requires_human_count": requires_human_count,
                "auto_fixable_count": auto_fixable_count,
                "advisories": filtered_advisories,
            });

            println!(
                "{}",
                serde_json::to_string_pretty(&wrapper)
                    .map_err(|e| FrensenseError::Config(format!("JSON error: {e}")))?
            );
        }
        "sarif" => {
            let sarif = Reporter::to_sarif(filtered_advisories, input_path);
            println!(
                "{}",
                serde_json::to_string_pretty(&sarif)
                    .map_err(|e| FrensenseError::Config(format!("JSON error: {e}")))?
            );
        }
        _ => {
            if filtered_advisories.is_empty() {
                println!("Analysis Complete: Looking great! No structural concerns found.");
            } else {
                println!("╔══════════════════════════════════════════════════╗");
                println!(
                    "║  Frensense v{}                              ║",
                    crate::FRENSENSE_VERSION
                );
                println!("║  Semantic Code Analysis Engine                ║");
                println!("╚══════════════════════════════════════════════════╝");
                println!("Analysis: {}", input_path.display());
                println!();
                for v in filtered_advisories {
                    let severity_label = match v.severity {
                        crate::Severity::Critical => "[CRITICAL]",
                        crate::Severity::Warning => "[WARNING]",
                        crate::Severity::Info => "[INFO]",
                    };
                    println!(
                        "{} {}: {} ({}:{}:{})",
                        severity_label, v.rule_id, v.observation, v.file_path, v.line, v.column
                    );
                    if let Some(ref ev) = v.match_evidence {
                        println!("{}", format_evidence(ev));
                    }
                    println!("   - Impact: {}", v.impact);
                    println!("   - Suggestion: {}\n", v.improvement);
                }
                println!("Total Review Suggestions: {}", filtered_advisories.len());
            }
        }
    }
    Ok(())
}

/// Compare the current findings against a baseline.
///
/// # Errors
/// Returns an error if the baseline file cannot be read or parsed.
pub fn compare_baseline(filtered_advisories: &[Advisory], path: &str) -> Result<bool> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| FrensenseError::Config(format!("Failed to read baseline: {e}")))?;
    let baseline: Vec<Advisory> = serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .map_err(|e| FrensenseError::Config(format!("Failed to parse baseline: {e}")))?;

    let baseline_fuzzy: HashSet<_> = baseline.iter().map(Advisory::fuzzy_identity).collect();
    let current_fuzzy: HashSet<_> = filtered_advisories
        .iter()
        .map(Advisory::fuzzy_identity)
        .collect();

    let new_advisories: Vec<_> = filtered_advisories
        .iter()
        .filter(|a| !baseline_fuzzy.contains(&a.fuzzy_identity()))
        .collect();
    let resolved_advisories: Vec<_> = baseline
        .iter()
        .filter(|a| !current_fuzzy.contains(&a.fuzzy_identity()))
        .collect();

    let mut regression_detected = false;
    if new_advisories.is_empty() {
        println!("\n[OK] No new advisories compared to baseline.");
    } else {
        println!(
            "\n[REGRESSION] {} new advisories detected!",
            new_advisories.len()
        );
        for adv in &new_advisories {
            println!("  + {}:{} ({})", adv.file_path, adv.line, adv.rule_id);
        }
        regression_detected = true;
    }

    if !resolved_advisories.is_empty() {
        println!(
            "[OK] {} advisories resolved since baseline.",
            resolved_advisories.len()
        );
    }

    let new_len: i128 = new_advisories.len() as i128;
    let resolved_len: i128 = resolved_advisories.len() as i128;
    let net = i64::try_from(new_len).unwrap_or(0) - i64::try_from(resolved_len).unwrap_or(0);
    println!(
        "[NET] {} ({} total findings)\n",
        if net > 0 {
            format!("+{net}")
        } else {
            net.to_string()
        },
        filtered_advisories.len()
    );
    Ok(regression_detected)
}

/// Save the current findings as a baseline.
///
/// # Errors
/// Returns an error if the baseline file cannot be written.
pub fn save_baseline(advisories: &[Advisory], path: &str) -> Result<()> {
    let content = serde_json::to_string_pretty(advisories)
        .map_err(|e| FrensenseError::Config(format!("JSON error: {e}")))?;
    std::fs::write(path, content)
        .map_err(|e| FrensenseError::Config(format!("Failed to write baseline: {e}")))?;
    println!("[SUCCESS] Captured baseline to {path}");
    Ok(())
}

/// Extract a category string from a rule_id for grouping purposes.
/// Rule IDs follow the format `CORPUS_LANG_CATEGORY_...` or `BUILTIN_NAME`.
/// We extract the category segment (e.g., "SSRF", "CMDI", "SQLI") for dedup grouping.
fn rule_category(rule_id: &str) -> &str {
    let parts: Vec<&str> = rule_id.split('_').collect();
    if parts.len() >= 3 && parts[0] == "CORPUS" {
        parts[2] // e.g., "SSRF" from "CORPUS_TS_SSRF_FETCH_DIRECT_M4"
    } else {
        "default"
    }
}

pub fn deduplicate_advisories(advisories: &mut Vec<Advisory>) {
    // Group by (file_path, function_name, category), keep highest confidence per group.
    // This collapses 50+ pattern matches on the same function into ~1 per vulnerability category.
    // When the enclosing symbol is unknown, include the rule_id and line to avoid collapsing
    // independent findings from different detection modules.
    let mut best: std::collections::HashMap<(String, String, String, String, u32), usize> =
        std::collections::HashMap::new();
    let mut keep = vec![true; advisories.len()];

    for (i, adv) in advisories.iter().enumerate() {
        let fn_name = adv
            .enclosing_symbol
            .as_deref()
            .unwrap_or("<unknown>")
            .to_string();
        let category = rule_category(&adv.rule_id).to_string();
        let group_id = if fn_name == "<unknown>" || category == "default" {
            // For unknown enclosing symbols or non-CORPUS findings, include rule_id
            // to prevent collapsing independent findings from different modules.
            format!("{}:{}", category, adv.rule_id)
        } else {
            category
        };
        let key = (
            adv.file_path.clone(),
            fn_name,
            group_id,
            adv.rule_id.clone(),
            adv.line,
        );
        match best.get(&key) {
            Some(&prev_idx) if advisories[prev_idx].confidence >= adv.confidence => {
                keep[i] = false;
            }
            Some(&prev_idx) => {
                keep[prev_idx] = false;
                best.insert(key, i);
            }
            None => {
                best.insert(key, i);
            }
        }
    }

    // Remove deduplicated advisories (in reverse to preserve indices)
    for i in (0..advisories.len()).rev() {
        if !keep[i] {
            let _ = advisories.swap_remove(i);
        }
    }
}

pub fn apply_filters(advisories: &mut Vec<Advisory>, options: &CliOptions, engine: &Engine) {
    advisories.retain(|a| a.confidence >= options.min_confidence);

    if !options.enabled_tags.is_empty() {
        advisories.retain(|a| {
            engine.auditor().rules().iter().any(|r| {
                r.id() == a.rule_id
                    && options
                        .enabled_tags
                        .iter()
                        .any(|t| r.metadata().tags.iter().any(|rt| rt == t))
            })
        });
    }

    if let Some(filter) = options.severity_filter {
        advisories.retain(|a| a.severity.meets_threshold(filter));
    }

    // Deduplicate: keep highest-confidence advisory per (file, function, category)
    deduplicate_advisories(advisories);
}
