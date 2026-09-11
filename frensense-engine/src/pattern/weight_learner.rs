use std::collections::HashMap;

pub type FeatureVec = [f64; 15];

// [ngram, ast, sig, ptype, tuse, sem, cf, API, taint, motif, flow, cfg, cfOrd, argT, litC]
// Prior: API=0.25 + taint=0.30 = 0.55 — too dominant for TS/Node frameworks where these calls
// appear in clean code as frequently as in vulnerable code.
// Rebalanced: API=0.14 + taint=0.13 = 0.27, with weight redistributed to structural dims.
pub const DEFAULT_WEIGHTS: FeatureVec = [
    0.09, 0.13, 0.06, 0.02, 0.02, 0.09, 0.08, 0.12, 0.10, 0.06, 0.07, 0.03, 0.03, 0.05, 0.05,
];

pub fn extract_category(pattern_id: &str) -> &str {
    pattern_id.split('_').nth(1).unwrap_or("")
}

pub fn category_weights<'a>(
    pattern_id: &str,
    learned: &'a HashMap<String, FeatureVec>,
) -> &'a FeatureVec {
    if let Some(w) = learned.get(pattern_id) {
        return w;
    }
    let cat = extract_category(pattern_id);
    learned.get(cat).unwrap_or(&DEFAULT_WEIGHTS)
}
