use crate::fingerprint::FunctionFingerprint;

#[derive(Debug, Default, Clone, Copy)]
pub struct RawDimensions {
    pub ngram_sim: f64,
    pub ast_sim: f64,
    pub signature_sim: f64,
    pub param_type_sim: f64,
    pub type_usage_sim: f64,
    pub semantic_sim: f64,
    pub cf_sim: f64,
    pub api_sim: f64,
    pub tainted_api_sim: f64,
    pub motif_sim: f64,
    pub flow_sim: f64,
    pub config_sim: f64,
    pub cf_order_sim: f64,
    pub arg_type_sim: f64,
    pub literal_concat_sim: f64,
}

impl RawDimensions {
    pub fn weighted_score(&self, w: &[f64; 15]) -> f64 {
        // OPTION B: Multiplicative Gating
        // Identity Prerequisites
        let identity_gate = self
            .api_sim
            .max(self.semantic_sim)
            .max(self.ast_sim)
            .max(self.motif_sim)
            .max(self.flow_sim);

        // Soft multiplier: if identity is 0, score drops by 90%. If identity > 0.4, score is preserved.
        let gate = (identity_gate * 2.5 + 0.1).min(1.0);

        // Vulnerability Indicators (we still use their weights, but we omit the identity dimensions to avoid double-counting, or just keep them)
        let vuln_score = self.ngram_sim * w[0]
            + self.ast_sim * w[1]
            + self.signature_sim * w[2]
            + self.param_type_sim * w[3]
            + self.type_usage_sim * w[4]
            + self.semantic_sim * w[5]
            + self.cf_sim * w[6]
            + self.api_sim * w[7]
            + self.tainted_api_sim * w[8]
            + self.motif_sim * w[9]
            + self.flow_sim * w[10]
            + self.config_sim * w[11]
            + self.cf_order_sim * w[12]
            + self.arg_type_sim * w[13]
            + self.literal_concat_sim * w[14];

        vuln_score * gate
    }

    pub fn as_array(&self) -> [f64; 15] {
        [
            self.ngram_sim,
            self.ast_sim,
            self.signature_sim,
            self.param_type_sim,
            self.type_usage_sim,
            self.semantic_sim,
            self.cf_sim,
            self.api_sim,
            self.tainted_api_sim,
            self.motif_sim,
            self.flow_sim,
            self.config_sim,
            self.cf_order_sim,
            self.arg_type_sim,
            self.literal_concat_sim,
        ]
    }

    pub fn apply_semantic_override(&self, base_score: f64) -> f64 {
        let identity_gate = self
            .api_sim
            .max(self.semantic_sim)
            .max(self.ast_sim)
            .max(self.motif_sim);

        // Data flow paths are abstract (they hash SemanticMarkers like SqlSink, not raw strings).
        // Therefore, flow_sim generalizes across frameworks perfectly!
        // We drop the motif_sim requirement because motif hashes use exact API strings which don't cross frameworks.
        if self.flow_sim > 0.8 && identity_gate > 0.1 {
            return base_score.max(0.85);
        }
        base_score
    }
}

pub fn jaccard(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let mut intersection = 0;
    for hash in a {
        if b.contains(hash) {
            intersection += 1;
        }
    }
    let union = a.len() + b.len() - intersection;
    if union == 0 {
        return 0.0;
    }
    (intersection as f64) / (union as f64)
}

pub fn jaccard_sorted(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let mut intersection = 0;
    let mut i = 0;
    let mut j = 0;
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            intersection += 1;
            i += 1;
            j += 1;
        } else if a[i] < b[j] {
            i += 1;
        } else {
            j += 1;
        }
    }
    let union = a.len() + b.len() - intersection;
    if union == 0 {
        0.0
    } else {
        (intersection as f64) / (union as f64)
    }
}

pub fn containment(candidate: &[u64], target: &[u64]) -> f64 {
    if candidate.is_empty() && target.is_empty() {
        return 0.0;
    }
    if target.is_empty() {
        return 0.0; // If target is empty, we cannot contain it. Return 0.0 so it doesn't hallucinate 1.0.
    }
    if candidate.is_empty() {
        return 0.0;
    }
    let mut intersection = 0;
    let mut i = 0;
    let mut j = 0;
    while i < candidate.len() && j < target.len() {
        if candidate[i] == target[j] {
            intersection += 1;
            i += 1;
            j += 1;
        } else if candidate[i] < target[j] {
            i += 1;
        } else {
            j += 1;
        }
    }
    (intersection as f64) / (target.len() as f64)
}

pub fn type_usage_overlap(a: &FunctionFingerprint, b: &FunctionFingerprint) -> f64 {
    if a.type_usages.is_empty() && b.type_usages.is_empty() {
        return 0.0;
    }
    if a.type_usages.is_empty() || b.type_usages.is_empty() {
        return 0.0;
    }
    if a.type_usages.len() == 1 {
        return if b.type_usages.contains(&a.type_usages[0]) {
            1.0
        } else {
            0.0
        };
    }
    if b.type_usages.len() == 1 {
        return if a.type_usages.contains(&b.type_usages[0]) {
            1.0
        } else {
            0.0
        };
    }
    let set_a: rustc_hash::FxHashSet<_> = a.type_usages.iter().collect();
    let set_b: rustc_hash::FxHashSet<_> = b.type_usages.iter().collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

pub fn lcs_similarity(candidate: &[u64], target: &[u64]) -> f64 {
    let n = candidate.len();
    let m = target.len();
    if n == 0 || m == 0 {
        return 0.0;
    }
    // Prevent OOM: if sequence is too large, fallback to jaccard
    if n > 2000 || m > 2000 {
        return jaccard_sorted(candidate, target);
    }
    // Use O(min(N,M)) space: only need two rows
    let mut prev = vec![0; m + 1];
    let mut curr = vec![0; m + 1];
    for i in 1..=n {
        for j in 1..=m {
            if candidate[i - 1] == target[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = std::cmp::max(prev[j], curr[j - 1]);
            }
        }
        prev.copy_from_slice(&curr);
    }
    let lcs = curr[m] as f64;
    let max_len = std::cmp::max(n, m) as f64;
    lcs / max_len
}

pub fn compute_dimensions(
    candidate: &FunctionFingerprint,
    target: &FunctionFingerprint,
) -> RawDimensions {
    let ngram_sim =
        if candidate.weighted_ngram_hashes.is_empty() || target.weighted_ngram_hashes.is_empty() {
            jaccard(&candidate.ngram_hashes, &target.ngram_hashes)
        } else {
            crate::pattern::scorer::weighted_jaccard(
                &candidate.weighted_ngram_hashes,
                &target.weighted_ngram_hashes,
            )
        };

    let semantic_sim = jaccard(&candidate.semantic_markers, &target.semantic_markers);

    let ast_sim = if !candidate.skeleton_hashes.is_empty()
        && !target.skeleton_hashes.is_empty()
        && ngram_sim > 0.25
    {
        1.0 - crate::ast_distance::tree_edit_distance(
            &candidate.skeleton_hashes,
            &target.skeleton_hashes,
        )
    } else {
        jaccard(&candidate.structural_markers, &target.structural_markers)
    };

    let signature_sim = jaccard_sorted(&candidate.signature_ngrams, &target.signature_ngrams);
    let param_type_sim = jaccard_sorted(&candidate.param_type_ngrams, &target.param_type_ngrams);
    let type_usage_sim = type_usage_overlap(candidate, target);
    let cf_sim = jaccard(&candidate.control_flow_hashes, &target.control_flow_hashes);

    let api_sim_full = jaccard(&candidate.api_calls, &target.api_calls);
    let api_sim_seg =
        if !candidate.api_call_segments.is_empty() && !target.api_call_segments.is_empty() {
            jaccard(&candidate.api_call_segments, &target.api_call_segments)
        } else {
            0.0
        };
    let api_sim = api_sim_full.max(api_sim_seg);

    let motif_sim = containment(&candidate.motif_hashes, &target.motif_hashes);
    let flow_sim = containment(
        &candidate.data_flow_path_hashes,
        &target.data_flow_path_hashes,
    );

    // Mutual empty MUST be 1.0 so that weights don't zero out!
    let tainted_api_sim =
        if candidate.tainted_api_calls.is_empty() && target.tainted_api_calls.is_empty() {
            0.0
        } else if candidate.tainted_api_calls.is_empty() {
            0.0
        } else if target.tainted_api_calls.is_empty() {
            jaccard_sorted(&candidate.tainted_api_calls, &target.api_calls)
        } else {
            jaccard_sorted(&candidate.tainted_api_calls, &target.tainted_api_calls)
        };

    let config_sim = jaccard(
        &candidate.config_literal_hashes,
        &target.config_literal_hashes,
    );

    let cf_order_sim =
        if candidate.control_flow_sequence.is_empty() && target.control_flow_sequence.is_empty() {
            0.0
        } else {
            lcs_similarity(
                &candidate.control_flow_sequence,
                &target.control_flow_sequence,
            )
        };

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

    RawDimensions {
        ngram_sim,
        ast_sim,
        signature_sim,
        param_type_sim,
        type_usage_sim,
        semantic_sim,
        cf_sim,
        api_sim,
        motif_sim,
        flow_sim,
        tainted_api_sim,
        config_sim,
        cf_order_sim,
        arg_type_sim,
        literal_concat_sim,
    }
}
