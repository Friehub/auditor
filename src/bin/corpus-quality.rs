#![allow(unused)]
#![allow(clippy::all)]
#![allow(clippy::all)]
#![allow(clippy::all)]
#![allow(dead_code, unreachable_patterns, unreachable_code)]
// SPDX-License-Identifier: MIT
//! Corpus quality scoring tool.
//!
//! Scores each positive/negative pair on 0-100 based on structural quality
//! heuristics. Outputs TSV sorted by score ascending - lowest first.
//!
//! Usage: cargo run --bin corpus-quality -- <corpus_dir>

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let corpus_dir = args.get(1).cloned().unwrap_or_else(|| {
        eprintln!("Usage: corpus-quality <corpus_dir>");
        std::process::exit(1);
    });
    let dir = std::path::Path::new(&corpus_dir);

    let files = collect_files(dir);
    let mut scores: Vec<(u32, String, Vec<String>)> = Vec::new();

    // Group by pattern ID
    use std::collections::HashMap;
    let mut by_pattern: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for path in &files {
        let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        // Normalize: strip _positive2, _positive3, _negative2, _negative3, _negative4, _m1_async, etc.
        // down to the base pattern name.
        let mut normalized = name.to_string();
        for suffix in &[
            "_positive9",
            "_positive8",
            "_positive7",
            "_positive6",
            "_positive5",
            "_positive4",
            "_positive3",
            "_positive2",
            "_negative5",
            "_negative4",
            "_negative3",
            "_negative2",
            "_positive",
            "_negative",
        ] {
            if let Some(stripped) = normalized.strip_suffix(suffix) {
                normalized = stripped.to_string();
                break;
            }
        }
        if !normalized.is_empty() {
            by_pattern.entry(normalized).or_default().push(path.clone());
        }
    }

    for (pattern, files) in &by_pattern {
        let pos: Vec<&PathBuf> = files
            .iter()
            .filter(|p| {
                let name = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                name.contains("_positive")
            })
            .collect();
        let mut negs: Vec<&PathBuf> = files
            .iter()
            .filter(|p| {
                let name = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                name.contains("_negative")
            })
            .collect();
        // Sort negatives so _negative.ts comes first
        negs.sort_by_key(|p| {
            let name = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if name.ends_with("_negative") { 0 } else { 1 }
        });

        let Some(pos_path) = pos.first() else {
            continue;
        };
        let src = match std::fs::read_to_string(pos_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Determine tier from pattern ID
        let cat = pattern.split('_').nth(1).unwrap_or("");
        let tier = classify_tier(cat, pattern);

        let mut score: u32 = 0;
        let mut checks: Vec<String> = Vec::new();
        let lower = src.to_lowercase();

        // +20 Has [frensense] block with all 3 fields
        let has_obs = src.contains("observation:");
        let has_imp = src.contains("impact:");
        let has_impv = src.contains("improvement:");
        if has_obs && has_imp && has_impv {
            score += 20;
        } else {
            checks.push("no_full_frensense".to_string());
        }

        // +15 Has at least one import statement
        if lower.contains("import ") || lower.contains("require(") {
            score += 15;
        } else {
            checks.push("no_import".to_string());
        }

        // +15 Has 2+ functions
        let fn_count = src.matches("function ").count() + src.matches("=>").count() / 2;
        if fn_count >= 2 {
            score += 15;
        } else {
            checks.push("under_2_functions".to_string());
        }

        // +15 Typed HTTP handler parameter
        if lower.contains("express.request")
            || lower.contains("express.response")
            || lower.contains(": request")
            || lower.contains(": response")
            || lower.contains(": context")
            || lower.contains("req: request")
            || lower.contains("res: response")
        {
            score += 15;
        } else {
            checks.push("untyped_handler".to_string());
        }

        // +10 Taint source is explicit
        if lower.contains("req.body")
            || lower.contains("req.query")
            || lower.contains("req.params")
            || lower.contains("req.headers")
            || lower.contains("req.cookies")
            || lower.contains("c.req")
            || lower.contains("ctx.request")
        {
            score += 10;
        } else {
            checks.push("no_taint_source".to_string());
        }

        // +10 Has CWE in [frensense] block
        if lower.contains("cwe:") {
            score += 10;
        } else {
            checks.push("no_cwe".to_string());
        }

        // +10 Negative uses same sink call safely
        if let Some(neg_path) = negs.first() {
            if let Ok(neg_src) = std::fs::read_to_string(neg_path) {
                let pos_imports: Vec<&str> = src
                    .lines()
                    .filter(|l| l.trim().starts_with("import ") || l.trim().starts_with("const "))
                    .collect();
                let neg_imports: Vec<&str> = neg_src
                    .lines()
                    .filter(|l| l.trim().starts_with("import ") || l.trim().starts_with("const "))
                    .collect();
                if !pos_imports.is_empty() && !neg_imports.is_empty() {
                    score += 10;
                } else {
                    checks.push("neg_no_same_imports".to_string());
                }
            } else {
                checks.push("neg_unreadable".to_string());
            }
        } else {
            checks.push("no_negative".to_string());
        }

        // === Tier-specific requirements (from FRENSENSE_CORPUS_GUIDE.md) ===
        let pos_count = pos.len();
        let neg_count = negs.len();
        let mut mut_count = 0usize;
        for f in files {
            let name = f.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            // Count mutation variants: files with m1, m2, m3 etc. in the name
            // that don't start with "negative" (positives that are also mutations)
            if name.contains("_m") && name.contains("_positive") {
                mut_count += 1;
            }
        }

        // Tier 1: requires ≥7 positives (base + 4 mutations) + ≥4 negatives
        // Tier 2: requires ≥5 positives + ≥3 negatives
        // Tier 3: requires ≥4 positives + ≥2 negatives
        // Tier 4: requires ≥3 positives + ≥2 negatives
        // Tier 5: requires ≥2 positives + ≥1 negative
        let (needed_pos, needed_neg): (i32, i32) = match tier {
            1 => (7, 4),
            2 => (5, 3),
            3 => (4, 2),
            4 => (3, 2),
            _ => (2, 1),
        };

        let pos_gap = needed_pos - pos_count as i32;
        let neg_gap = needed_neg - neg_count as i32;
        if pos_gap > 0 {
            score = score.saturating_sub((pos_gap as u32) * 5);
            checks.push(format!("need_{}_more_pos_tier{tier}", pos_gap));
        }
        if neg_gap > 0 {
            score = score.saturating_sub((neg_gap as u32) * 5);
            checks.push(format!("need_{}_more_neg_tier{tier}", neg_gap));
        }

        // Tier 1: cvss + runtime_probe required
        if tier == 1 && !lower.contains("cvss:") {
            checks.push("tier1_missing_cvss".to_string());
        }
        if tier == 1 && !lower.contains("runtime_probe:") {
            checks.push("tier1_missing_runtime_probe".to_string());
        }

        // Tier 2: owasp required
        if tier == 2 && !lower.contains("owasp:") {
            checks.push("tier2_missing_owasp".to_string());
        }

        // Tier 3: exploit_scenario required
        if tier == 3 && !lower.contains("exploit_scenario:") {
            checks.push("tier3_missing_exploit_scenario".to_string());
        }

        // Tier 4: reference required
        if tier == 4 && !lower.contains("reference:") {
            checks.push("tier4_missing_reference".to_string());
        }

        // -20 File under 10 lines
        let line_count = src.lines().count();
        if line_count < 10 {
            score = score.saturating_sub(20);
            checks.push("under_10_lines".to_string());
        }

        // -20 Placeholder names
        for placeholder in &["foo", "bar", "test", "dostuff", "dothing", "dosth"] {
            if lower.contains(placeholder) {
                score = score.saturating_sub(20);
                checks.push("placeholder_names".to_string());
                break;
            }
        }

        // -10 req typed as any throughout
        let any_count = src.matches(": any").count();
        if any_count >= 3 {
            score = score.saturating_sub(10);
            checks.push("excessive_any".to_string());
        }

        // -10 Only one function
        if fn_count < 2 {
            score = score.saturating_sub(10);
        }

        scores.push((score, pattern.clone(), checks));
    }

    // Summary by tier
    let mut by_tier: [u32; 6] = [0; 6];
    let mut below50_by_tier: [u32; 6] = [0; 6];
    for (score, pattern, _) in &scores {
        let cat = pattern.split('_').nth(1).unwrap_or("");
        let t = classify_tier(cat, pattern);
        by_tier[t] += 1;
        if *score < 50 {
            below50_by_tier[t] += 1;
        }
    }
    eprintln!();
    for t in 1..=5 {
        eprintln!(
            "  Tier {t}: {} patterns ({} below 50)",
            by_tier[t], below50_by_tier[t]
        );
    }

    // Sort by score ascending
    scores.sort_by_key(|(s, _, _)| *s);

    // Output TSV
    println!("score\tpattern_id\tfailing_checks");
    for (score, pattern, checks) in &scores {
        println!("{}\t{}\t{}", score, pattern, checks.join(","));
    }

    // Summary
    let total = scores.len();
    let below_50 = scores.iter().filter(|(s, _, _)| *s < 50).count();
    let above_80 = scores.iter().filter(|(s, _, _)| *s >= 80).count();
    eprintln!("\nScored {total} patterns: {below_50} below 50, {above_80} above 80");
}

fn collect_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    collect_recursive(dir, &mut result);
    result
}

/// Classify a pattern into a tier (1-5) based on its category prefix.
fn classify_tier(cat: &str, pattern: &str) -> usize {
    let tier1 = [
        "cmdi",
        "sqli",
        "ssrf",
        "xss",
        "path",
        "open",
        "eval",
        "ldap",
        "xpath",
        "ssti",
        "nosqli",
        "xxe",
        "prototype",
        "deserialization",
    ];
    let tier2 = [
        "jwt",
        "auth",
        "idor",
        "bac",
        "rbac",
        "cors",
        "csrf",
        "session",
        "oauth",
        "oidc",
        "cookie",
        "mfa",
        "ratelimit",
    ];
    let tier3 = [
        "race",
        "toctou",
        "integer",
        "deadlock",
        "payment",
        "ownership",
    ];
    let tier4 = [
        "crypto",
        "hardcoded",
        "regex",
        "env",
        "debug",
        "rand",
        "weak",
        "error",
    ];
    // Tier 5: anything React/LLM/Rust-specific not in tiers 1-4
    if pattern.contains("tsx_")
        || pattern.contains("llm_")
        || pattern.contains("rust_async")
        || pattern.contains("rust_transmute")
        || pattern.contains("edition2024")
    {
        return 5;
    }
    if tier1.contains(&cat) {
        return 1;
    }
    if tier2.contains(&cat) {
        return 2;
    }
    if tier3.contains(&cat) {
        return 3;
    }
    if tier4.contains(&cat) {
        return 4;
    }
    // Default: Tier 5 (framework-specific / unclassified)
    5
}

fn collect_recursive(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(&path, out);
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if matches!(ext, "ts" | "tsx" | "js" | "jsx" | "rs") {
                    out.push(path);
                }
            }
        }
    }
}
