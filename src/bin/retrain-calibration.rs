#![allow(unused)]
#![allow(clippy::all)]
// SPDX-License-Identifier: MIT
//! Retrain calibration parameters from corpus data.
//!
//! Usage: cargo run --bin retrain-calibration
//!
//! Scores all corpus positive examples against their patterns (TP)
//! and negative examples against positive patterns (FP),
//! then trains Platt scaling parameters.

use frensense::engine::confidence_calibration::{CalibrationParams, save_calibration};
use frensense_bundler::loader::load_corpus;
use frensense_engine::fingerprint::{apply_idf_weights, compute_idf_weights};
use frensense_engine::pattern::scorer::PatternScorer;
use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let corpus_dir = Path::new(&manifest_dir).join("corpus").join("targets");

    eprintln!("Loading corpus from {}...", corpus_dir.display());
    let (patterns, _warnings) = load_corpus(&corpus_dir).expect("Failed to load corpus");

    // Compute IDF weights from all positive fingerprints
    let all_positives: Vec<_> = patterns
        .iter()
        .flat_map(|p| p.positives.iter().cloned())
        .collect();
    let idf_weights = compute_idf_weights(&all_positives);
    eprintln!("Computed IDF weights for {} n-grams", idf_weights.len());

    let mut scores: Vec<(f64, bool)> = Vec::new();

    for pattern in &patterns {
        // Apply IDF weights to pattern fingerprints
        let mut pos_fps: Vec<_> = pattern.positives.clone();
        let mut neg_fps: Vec<_> = pattern.negatives.clone();

        for fp in &mut pos_fps {
            apply_idf_weights(fp, &idf_weights);
        }
        for fp in &mut neg_fps {
            apply_idf_weights(fp, &idf_weights);
        }

        let default_w = &[
            0.10, 0.20, 0.08, 0.04, 0.03, 0.10, 0.08, 0.06, 0.12, 0.06, 0.10, 0.03, 0.02, 0.04,
            0.04,
        ];

        // Score positive examples against their own pattern (should be high = TP)
        for pos in &pos_fps {
            let score = PatternScorer::score_against_corpus(
                pos, &pos_fps, &neg_fps, None, None, 0.05, default_w,
            );
            scores.push((score, true));
        }

        // Score negative examples against positive pattern (should be low = FP)
        for neg in &neg_fps {
            let score = PatternScorer::score_against_corpus(
                neg, &pos_fps, &neg_fps, None, None, 0.05, default_w,
            );
            scores.push((score, false));
        }
    }

    eprintln!(
        "Generated {} labeled scores (TP={}, FP={})",
        scores.len(),
        scores.iter().filter(|(_, l)| *l).count(),
        scores.iter().filter(|(_, l)| !*l).count(),
    );

    // Train calibration parameters
    let score_values: Vec<f64> = scores.iter().map(|(s, _)| *s).collect();
    let labels: Vec<bool> = scores.iter().map(|(_, l)| *l).collect();

    let params = CalibrationParams::train(&score_values, &labels);

    eprintln!("Trained calibration parameters:");
    eprintln!("  a = {:.6}", params.a);
    eprintln!("  b = {:.6}", params.b);
    eprintln!("  n_samples = {}", params.n_samples);
    eprintln!("  accuracy = {:.4}", params.accuracy);

    // Verify calibration produces reasonable probabilities
    let test_scores = [0.3, 0.5, 0.7, 0.9];
    eprintln!("\nCalibration mapping:");
    for &s in &test_scores {
        eprintln!("  raw={:.2} → calibrated={:.4}", s, params.calibrate(s));
    }

    // Save to calibration.json
    let output_path = Path::new(&manifest_dir).join("calibration.json");
    save_calibration(&params, &output_path).expect("Failed to save calibration");
    eprintln!("\nSaved calibration to {}", output_path.display());
}
