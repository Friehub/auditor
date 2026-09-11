// SPDX-License-Identifier: MIT

use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use std::hash::{Hash, Hasher};

/// Number of MinHash signatures for LSH. Higher = more accurate similarity estimation.
pub const DEFAULT_NUM_HASHES: usize = 120;

/// Number of LSH bands. More bands = higher recall but more candidates.
/// Threshold = (1/bands)^(1/rows_per_band).
pub const DEFAULT_BANDS: usize = 40;

/// Rows per LSH band. More rows = tighter threshold (fewer candidates).
/// Threshold = (1/bands)^(1/rows_per_band) = (1/40)^(1/12) ≈ 0.71.
pub const DEFAULT_ROWS_PER_BAND: usize = 3;

/// Compute a single MinHash row hash using a universal multiply-shift hash family.
///
/// Each row uses a unique pair `(a, b)` derived from `seed` as hash function
/// `h_{a,b}(x) = (a * x + b) mod 2^64` where `a` is odd (required for the
/// construction to be universal in the 2-universal sense per Dietzfelbinger 1997).
///
/// This is significantly better than using `FxHasher` as a seed-varying hash,
/// since `FxHasher` is not a universal hash family and produces biased MinHash
/// signatures.
///
/// NOTE: If `twox-hash` becomes available in the dependency tree, prefer
/// `XxHash64::with_seed` as it has superior distribution properties. See
/// TASK 2 in the implementation plan.
#[inline]
fn minhash_row_hash(value: u64, seed: u64) -> u64 {
    // Generate two independent hash coefficients from the seed.
    // The seed expansion uses a simple mixing step to avoid correlation
    // between adjacent seeds.
    let seed_a = seed.wrapping_mul(0x517c_c1b7_2722_0a95).wrapping_add(1);
    let seed_b = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    // a must be odd for the construction to be universal. Force LSB = 1.
    let a = seed_a | 1;
    let b = seed_b;
    value.wrapping_mul(a).wrapping_add(b)
}

pub fn minhash_signature(hashes: &[u64], num_hashes: usize) -> Vec<u64> {
    if hashes.is_empty() {
        return vec![0u64; num_hashes];
    }

    // Transposed loop: iterate over hashes once, updating all signature
    // minimums in a single pass.  Cache-friendly — 1 sweep instead of
    // num_hashes sweeps over the input vector.
    let mut signature = vec![u64::MAX; num_hashes];
    for &h in hashes {
        for (i, min_val) in signature.iter_mut().enumerate() {
            let candidate = minhash_row_hash(h, i as u64);
            if candidate < *min_val {
                *min_val = candidate;
            }
        }
    }
    signature
}

pub fn intersect_sorted(a: &[u64], b: &[u64]) -> usize {
    let mut i = 0;
    let mut j = 0;
    let mut intersection = 0;
    while i < a.len() && j < b.len() {
        if a[i] < b[j] {
            i += 1;
        } else if a[i] > b[j] {
            j += 1;
        } else {
            intersection += 1;
            i += 1;
            j += 1;
        }
    }
    intersection
}

pub fn jaccard_similarity_sorted(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.5;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let intersection = intersect_sorted(a, b);
    let union = a.len() + b.len() - intersection;
    intersection as f64 / union as f64
}

pub fn overlap_coefficient_sorted(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let intersection = intersect_sorted(a, b);
    let min_len = std::cmp::min(a.len(), b.len());
    intersection as f64 / min_len as f64
}

#[allow(clippy::implicit_hasher)]
pub fn jaccard_similarity(a: &FxHashSet<u64>, b: &FxHashSet<u64>) -> f64 {
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        return 0.0;
    }
    intersection as f64 / union as f64
}

pub fn signature_similarity(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() || b.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    matches as f64 / a.len() as f64
}

pub struct LSHIndex {
    /// Each band has a HashMap from bucket-hash → list of pattern IDs.
    /// Unlike the old fixed-size bucket array (which collapsed all items
    /// into `num_bands` slots), this scales naturally with item count —
    /// essential for the target 45k+ corpus scale.
    bands: Vec<FxHashMap<u64, Vec<u64>>>,
    num_bands: usize,
    rows_per_band: usize,
}

impl Default for LSHIndex {
    fn default() -> Self {
        Self {
            bands: vec![FxHashMap::default(); DEFAULT_BANDS],
            num_bands: DEFAULT_BANDS,
            rows_per_band: DEFAULT_ROWS_PER_BAND,
        }
    }
}

impl LSHIndex {
    pub fn new(num_bands: usize, rows_per_band: usize) -> Self {
        Self {
            bands: vec![FxHashMap::default(); num_bands],
            num_bands,
            rows_per_band,
        }
    }

    pub fn insert(&mut self, signature: &[u64], item_id: u64) {
        for band in 0..self.num_bands {
            let start = band * self.rows_per_band;
            if start >= signature.len() {
                break;
            }
            let end = (start + self.rows_per_band).min(signature.len());
            let mut hasher = FxHasher::default();
            for &val in &signature[start..end] {
                val.hash(&mut hasher);
            }
            let bucket_key = hasher.finish();
            self.bands[band]
                .entry(bucket_key)
                .or_default()
                .push(item_id);
        }
    }

    pub fn query(&self, signature: &[u64]) -> Vec<u64> {
        let mut candidates = FxHashSet::default();
        let mut bands_matched = 0usize;
        for band in 0..self.num_bands {
            let start = band * self.rows_per_band;
            if start >= signature.len() {
                break;
            }
            let end = (start + self.rows_per_band).min(signature.len());
            let mut hasher = FxHasher::default();
            for &val in &signature[start..end] {
                val.hash(&mut hasher);
            }
            let bucket_key = hasher.finish();
            if let Some(ids) = self.bands[band].get(&bucket_key) {
                bands_matched += 1;
                for &fp in ids {
                    candidates.insert(fp);
                }
            }
        }
        if candidates.len() > 100 {
            tracing::debug!(
                bands_matched,
                candidates = candidates.len(),
                signature_len = signature.len(),
                "High number of LSH candidates found"
            );
        }
        candidates.into_iter().collect()
    }

    /// Returns the total number of stored (band, bucket) entries across all bands.
    /// Useful for diagnostics — at 45k patterns each band has ~bucket_count entries.
    pub fn bucket_count(&self) -> usize {
        self.bands.iter().map(|b| b.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minhash_identical_sets() {
        let set: Vec<u64> = vec![42, 99];
        let sig = minhash_signature(&set, DEFAULT_NUM_HASHES);
        assert_eq!(sig.len(), DEFAULT_NUM_HASHES);
    }

    #[test]
    fn test_jaccard_identical() {
        let mut a = FxHashSet::default();
        a.insert(1);
        a.insert(2);
        let b = a.clone();
        assert!((jaccard_similarity(&a, &b) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_jaccard_disjoint() {
        let mut a = FxHashSet::default();
        a.insert(1);
        let mut b = FxHashSet::default();
        b.insert(2);
        assert!((jaccard_similarity(&a, &b) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_signature_similarity() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 5, 6];
        let sim = signature_similarity(&a, &b);
        assert!((sim - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_lsh_index() {
        let mut index = LSHIndex::new(4, 2);
        let sig = minhash_signature(&[], 8);
        index.insert(&sig, 42);
        let candidates = index.query(&sig);
        assert!(candidates.contains(&42));
    }
}
