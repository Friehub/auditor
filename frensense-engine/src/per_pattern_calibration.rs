// SPDX-License-Identifier: MIT

//! Per-pattern confidence calibration via logistic regression.
//!
//! Each pattern gets its own sigmoid:  P(tp | score) = 1 / (1 + exp(-(A·score + B)))
//! Trained at bundle build time by holding out 20% of positive/negative pairs,
//! scoring them against the pattern, and fitting (A, B) via gradient descent.
//!
//! Falls back to per-category Platt scaling when a pattern has fewer than
//! MIN_EXAMPLES training pairs.

use crate::fingerprint::FunctionFingerprint;
use crate::minhash;
use crate::pattern::similarity::type_usage_overlap;

/// Minimum number of scored examples required to fit a per-pattern sigmoid.
const MIN_EXAMPLES: usize = 10;

/// Sigmoid parameters:  P(tp | score) = 1 / (1 + exp(-(A * score + B)))
pub type CalibrationParams = (f32, f32);

/// Compute the 8-d feature vector for calibration scoring.
pub fn compute_calibration_features(
    candidate: &FunctionFingerprint,
    target: &FunctionFingerprint,
) -> f64 {
    let jaccard = |a: &[u64], b: &[u64]| minhash::jaccard_similarity_sorted(a, b);

    let ngram_sim =
        if candidate.weighted_ngram_hashes.is_empty() || target.weighted_ngram_hashes.is_empty() {
            jaccard(&candidate.ngram_hashes, &target.ngram_hashes)
        } else {
            let mut intersection = 0.0f64;
            let mut union_sum = 0.0f64;
            for (h, w) in &candidate.weighted_ngram_hashes {
                union_sum += *w as f64;
                if target.weighted_ngram_hashes.contains_key(h) {
                    intersection += *w as f64;
                }
            }
            for w in target.weighted_ngram_hashes.values() {
                union_sum += *w as f64;
            }
            if union_sum == 0.0 {
                0.0
            } else {
                intersection / union_sum
            }
        };
    let semantic_sim = jaccard(&candidate.semantic_markers, &target.semantic_markers);
    let ast_sim = if !candidate.skeleton_hashes.is_empty() && !target.skeleton_hashes.is_empty() {
        1.0 - crate::ast_distance::tree_edit_distance(
            &candidate.skeleton_hashes,
            &target.skeleton_hashes,
        )
    } else {
        jaccard(&candidate.structural_markers, &target.structural_markers)
    };
    let cf_sim = jaccard(&candidate.control_flow_hashes, &target.control_flow_hashes);
    // API sim: max of full-name and segment Jaccard (mirrors scorer)
    let api_sim_full = jaccard(&candidate.api_calls, &target.api_calls);
    let api_sim_seg =
        if !candidate.api_call_segments.is_empty() && !target.api_call_segments.is_empty() {
            jaccard(&candidate.api_call_segments, &target.api_call_segments)
        } else {
            0.0
        };
    let api_sim = api_sim_full.max(api_sim_seg);
    let tainted_api_sim = jaccard(&candidate.tainted_api_calls, &target.tainted_api_calls);

    let arg_type_sim =
        if !candidate.argument_call_types.is_empty() && !target.argument_call_types.is_empty() {
            jaccard(&candidate.argument_call_types, &target.argument_call_types)
        } else {
            0.0
        };
    let literal_concat_sim = if !candidate.literal_pattern_hashes.is_empty()
        && !target.literal_pattern_hashes.is_empty()
    {
        jaccard(
            &candidate.literal_pattern_hashes,
            &target.literal_pattern_hashes,
        )
    } else {
        0.0
    };

    // Use hardcoded fallback weights for calibration (avoids circular dependency)
    ngram_sim * 0.12
        + ast_sim * 0.20
        + jaccard(&candidate.signature_ngrams, &target.signature_ngrams) * 0.08
        + jaccard(&candidate.param_type_ngrams, &target.param_type_ngrams) * 0.04
        + type_usage_overlap(candidate, target) * 0.03
        + semantic_sim * 0.12
        + cf_sim * 0.12
        + api_sim * 0.12
        + tainted_api_sim * 0.17
        + arg_type_sim * 0.04
        + literal_concat_sim * 0.04
}

pub fn calibrate(raw_score: f64, params: Option<&(f32, f32)>) -> f64 {
    let (a, b) = match params {
        Some(&(a, b)) => (a as f64, b as f64),
        None => (8.0, -3.2), // Fallback Platt scaling
    };
    let z = a * raw_score + b;
    let z = z.clamp(-20.0, 20.0);
    let p = 1.0 / (1.0 + (-z).exp());
    if params.is_none() { p.min(0.55) } else { p }
}
