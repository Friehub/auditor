#![allow(unused)]
#![allow(clippy::all)]
// SPDX-License-Identifier: MIT
//! Inspects the FRC1 corpus bundle and prints diagnostics.
//!
//! Usage: cargo run --bin frensense-inspect [--bundle <path>]
//!
//! Without --bundle, loads the embedded bundle (frensense-corpus.frc).
//! With --bundle <path>, loads from the given file.

use frensense_engine::corpus::bundle::load_bundle;
use frensense_engine::pattern::scorer::ScorerConfig;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bundle_path = args
        .iter()
        .position(|a| a == "--bundle")
        .and_then(|i| args.get(i + 1).map(|p| PathBuf::from(p)));

    let bytes = if let Some(path) = &bundle_path {
        std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Error reading bundle: {e}");
            std::process::exit(1);
        })
    } else {
        include_bytes!("../../frensense-corpus.frc").to_vec()
    };

    let bundle = load_bundle(&bytes).unwrap_or_else(|e| {
        eprintln!("Error loading bundle: {e}");
        std::process::exit(1);
    });

    println!("=== FRC1 Corpus Bundle Diagnostics ===\n");
    println!(
        "Bundle size: {} bytes ({:.1} KB)",
        bytes.len(),
        bytes.len() as f64 / 1024.0
    );
    println!("Pattern count: {}", bundle.patterns.len());

    let total_pos: usize = bundle.patterns.iter().map(|p| p.positives.len()).sum();
    let total_neg: usize = bundle.patterns.iter().map(|p| p.negatives.len()).sum();
    println!(
        "Total fingerprints: {total_pos} positives + {total_neg} negatives = {}",
        total_pos + total_neg
    );

    println!("\n--- Pattern Inventory ---");

    let mut categories: std::collections::BTreeMap<String, Vec<&str>> =
        std::collections::BTreeMap::new();
    let mut languages: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut empty_advisories = 0usize;
    let mut has_cwe = 0usize;
    let mut has_cvss = 0usize;
    let mut has_severity = 0usize;
    let mut patterns_with_filter = 0usize;
    let mut single_pos = 0usize;
    let mut single_neg = 0usize;
    let mut large_pattern = 0usize;

    for pat in &bundle.patterns {
        // Category extraction: pattern name segments like "ts_sec_sql_injection_1"
        let parts: Vec<&str> = pat.id.split('_').collect();
        let category = if parts.len() >= 3 {
            parts[1]
        } else {
            "unknown"
        };
        categories
            .entry(category.to_string())
            .or_default()
            .push(&pat.id);

        // Language from first positive fingerprint
        if let Some(fp) = pat.positives.first() {
            *languages.entry(fp.language.clone()).or_insert(0) += 1;
        }

        if pat.observation.is_none() && pat.impact.is_none() && pat.improvement.is_none() {
            empty_advisories += 1;
        }
        if pat.cwe.is_some() {
            has_cwe += 1;
        }
        if pat.cvss.is_some() {
            has_cvss += 1;
        }
        if pat.severity.is_some() {
            has_severity += 1;
        }
        if pat.semantic_filter.is_some() {
            patterns_with_filter += 1;
        }
        if pat.positives.len() == 1 {
            single_pos += 1;
        }
        if pat.negatives.len() == 1 {
            single_neg += 1;
        }
        if pat.positives.len() + pat.negatives.len() > 10 {
            large_pattern += 1;
        }
    }

    println!("\n--- Categories ---");
    for (cat, pats) in &categories {
        println!("  {cat}: {} patterns", pats.len());
    }

    println!("\n--- Languages ---");
    for (lang, count) in &languages {
        println!("  {lang}: {count} patterns");
    }

    println!("\n--- Advisory Quality ---");
    println!("  Empty advisories (no observation/impact/improvement): {empty_advisories}");
    println!("  With CWE: {has_cwe}");
    println!("  With CVSS: {has_cvss}");
    println!("  With severity: {has_severity}");

    println!("\n--- Fingerprint Stats ---");
    println!("  Single positive patterns: {single_pos}");
    println!("  Single negative patterns: {single_neg}");
    println!("  Large patterns (>10 fingerprints): {large_pattern}");
    println!("  With semantic filter: {patterns_with_filter}");

    // Category weights
    if !bundle.category_weights.is_empty() {
        println!("\n--- Learned Category Weights ---");
        let dims = [
            "ngram", "ast", "sig", "ptyp", "tuse", "sem", "cf", "api", "tapi", "mot", "flow",
            "cfg", "cfo", "atyp", "lit",
        ];
        for (cat, weights) in &bundle.category_weights {
            print!("  {cat}: ");
            for (i, w) in weights.iter().enumerate() {
                print!("{}={:.3} ", dims[i], w);
            }
            println!();
        }
    }

    // Pattern calibration
    if !bundle.pattern_calibration.is_empty() {
        println!("\n--- Per-Pattern Calibration ---");
        let mut a_vals: Vec<f32> = bundle
            .pattern_calibration
            .iter()
            .map(|(_, a, _)| *a)
            .collect();
        let mut b_vals: Vec<f32> = bundle
            .pattern_calibration
            .iter()
            .map(|(_, _, b)| *b)
            .collect();
        a_vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
        b_vals.sort_by(|a, b| a.partial_cmp(b).unwrap());

        println!(
            "  A parameter: min={:.2}, median={:.2}, max={:.2}",
            a_vals[0],
            a_vals[a_vals.len() / 2],
            a_vals[a_vals.len() - 1]
        );
        println!(
            "  B parameter: min={:.2}, median={:.2}, max={:.2}",
            b_vals[0],
            b_vals[b_vals.len() / 2],
            b_vals[b_vals.len() - 1]
        );

        // Count sigmoid midpoints (where P(tp)=0.5)
        let midpoints: Vec<f32> = bundle
            .pattern_calibration
            .iter()
            .map(|(_, a, b)| -b / a)
            .collect();
        let mut midpoints_sorted = midpoints.clone();
        midpoints_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "  Score midpoint (P(tp)=0.5): min={:.3}, median={:.3}, max={:.3}",
            midpoints_sorted[0],
            midpoints_sorted[midpoints_sorted.len() / 2],
            midpoints_sorted.last().unwrap()
        );
    }

    // API IDF weights
    if !bundle.api_idf_weights.is_empty() {
        println!("\n--- API IDF Weights ---");
        println!(
            "  Total API tokens with IDF weights: {}",
            bundle.api_idf_weights.len()
        );
        let mut sorted = bundle.api_idf_weights.clone();
        sorted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        println!("  Lowest IDF (most common): {:.3}", sorted[0].1);
        println!("  Highest IDF (rarest): {:.3}", sorted.last().unwrap().1);
    }

    // Fingerprint dimension analysis
    println!("\n--- Fingerprint Dimension Analysis ---");
    let mut dim_counts = [0usize; 15];
    let dim_names = [
        "ngram", "ast", "sig", "ptyp", "tuse", "sem", "cf", "api", "tapi", "mot", "flow", "cfg",
        "cfo", "atyp", "lit",
    ];

    for pat in &bundle.patterns {
        for fp in pat.positives.iter().chain(pat.negatives.iter()) {
            if !fp.ngram_hashes.is_empty() {
                dim_counts[0] += 1;
            }
            if !fp.skeleton_hashes.is_empty() {
                dim_counts[1] += 1;
            }
            if !fp.signature_ngrams.is_empty() {
                dim_counts[2] += 1;
            }
            if !fp.param_type_ngrams.is_empty() {
                dim_counts[3] += 1;
            }
            if !fp.type_usages.is_empty() {
                dim_counts[4] += 1;
            }
            if !fp.semantic_markers.is_empty() {
                dim_counts[5] += 1;
            }
            if !fp.control_flow_hashes.is_empty() {
                dim_counts[6] += 1;
            }
            if !fp.api_calls.is_empty() {
                dim_counts[7] += 1;
            }
            if !fp.tainted_api_calls.is_empty() {
                dim_counts[8] += 1;
            }
            if !fp.motif_hashes.is_empty() {
                dim_counts[9] += 1;
            }
            if !fp.data_flow_path_hashes.is_empty() {
                dim_counts[10] += 1;
            }
            if !fp.config_literal_hashes.is_empty() {
                dim_counts[11] += 1;
            }
            if !fp.control_flow_sequence.is_empty() {
                dim_counts[12] += 1;
            }
            if !fp.argument_call_types.is_empty() {
                dim_counts[13] += 1;
            }
            if !fp.literal_pattern_hashes.is_empty() {
                dim_counts[14] += 1;
            }
        }
    }

    let total_fps = total_pos + total_neg;
    println!("  Dimension fill rates ({total_fps} total fingerprints):");
    for (i, name) in dim_names.iter().enumerate() {
        let pct = if total_fps > 0 {
            dim_counts[i] as f64 / total_fps as f64 * 100.0
        } else {
            0.0
        };
        let bar = "█".repeat((pct / 5.0) as usize);
        println!("    {name:>5}: {:>5} ({:>5.1}%) {bar}", dim_counts[i], pct);
    }

    // Current engine config
    println!("\n--- Current Engine Config ---");
    let config = ScorerConfig::default();
    println!("  cross_lingual_penalty: {}", config.cross_lingual_penalty);
    println!("  semantic_zero_penalty: {}", config.semantic_zero_penalty);
    println!("  semantic_match_boost: {}", config.semantic_match_boost);
    println!(
        "  noise_gate_strong_signal: {}",
        config.noise_gate_strong_signal
    );
    println!(
        "  noise_gate_moderate_signal: {}",
        config.noise_gate_moderate_signal
    );
    println!(
        "  noise_gate_min_moderate_dims: {}",
        config.noise_gate_min_moderate_dims
    );
    println!(
        "  min_best_positive_score: {}",
        config.min_best_positive_score
    );
    println!("  neg_penalty_floor: {}", config.neg_penalty_floor);
    println!("  neg_penalty_weight: {}", config.neg_penalty_weight);
    println!(
        "  context_mismatch_penalty: {}",
        config.context_mismatch_penalty
    );

    println!("\n--- Default Scoring Weights ---");
    let weights = [
        0.10, 0.20, 0.08, 0.04, 0.03, 0.10, 0.08, 0.06, 0.12, 0.06, 0.10, 0.03, 0.02, 0.04, 0.04,
    ];
    for (i, name) in dim_names.iter().enumerate() {
        let bar = "█".repeat((weights[i] * 50.0) as usize);
        println!("    {name:>5}: {:.2} {bar}", weights[i]);
    }

    // Pattern samples
    println!("\n--- Pattern Samples (first 10) ---");
    for pat in bundle.patterns.iter().take(10) {
        let obs = pat.observation.as_deref().unwrap_or("(none)");
        let cwe = pat.cwe.as_deref().unwrap_or("-");
        let cvss = pat
            .cvss
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  {} | {}+/{}/- | CWE={} CVSS={}",
            pat.id,
            pat.positives.len(),
            pat.negatives.len(),
            cwe,
            cvss
        );
        println!("    {}", if obs.len() > 80 { &obs[..80] } else { obs });
    }

    println!("\n=== Done ===");
}
