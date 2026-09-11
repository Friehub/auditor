// SPDX-License-Identifier: MIT

//! Near-duplicate function clustering using Union-Find.
//!
//! Groups functions into clusters based on `MinHash` similarity.
//! Identifies inconsistent implementations within clusters.

use frensense_engine::fingerprint::FunctionFingerprint;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct FunctionCluster {
    pub id: usize,
    pub members: Vec<ClusterMember>,
    pub has_inconsistency: bool,
}

#[derive(Debug, Clone)]
pub struct ClusterMember {
    pub fingerprint: FunctionFingerprint,
    pub cluster_role: ClusterRole,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClusterRole {
    /// This function is identical to others in the cluster
    Consistent,
    /// This function differs from others (potential bug)
    Inconsistent,
    /// This is the "safe" version (has sanitizer/validation)
    Safe,
    /// This is the "unsafe" version (missing validation)
    Unsafe,
}

/// Union-Find data structure for clustering.
struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, x: usize, y: usize) {
        let x_root = self.find(x);
        let y_root = self.find(y);

        if x_root == y_root {
            return;
        }

        match self.rank[x_root].cmp(&self.rank[y_root]) {
            std::cmp::Ordering::Less => self.parent[x_root] = y_root,
            std::cmp::Ordering::Greater => self.parent[y_root] = x_root,
            std::cmp::Ordering::Equal => {
                self.parent[y_root] = x_root;
                self.rank[x_root] += 1;
            }
        }
    }
}

/// Cluster functions by near-duplicate similarity.
#[must_use]
pub fn cluster_functions(
    fingerprints: &[FunctionFingerprint],
    similarity_threshold: f64,
) -> Vec<FunctionCluster> {
    if fingerprints.is_empty() {
        return Vec::new();
    }

    let n = fingerprints.len();
    let mut uf = UnionFind::new(n);

    // Build a MinHash signature once per fingerprint, then index them in an
    // LSH table so candidate discovery is sub-linear instead of O(n²).
    let signatures: Vec<Vec<u64>> = fingerprints
        .iter()
        .map(|fp| {
            frensense_engine::minhash::minhash_signature(
                &fp.ngram_hashes,
                frensense_engine::minhash::DEFAULT_NUM_HASHES,
            )
        })
        .collect();

    let mut index = frensense_engine::minhash::LSHIndex::default();
    for (i, sig) in signatures.iter().enumerate() {
        index.insert(sig, i as u64);
    }

    // Union only pairs that share an LSH band bucket. This turns the dominant
    // cost from n² full comparisons into n · k, where k is the average number
    // of candidates returned per query (≈ log n).
    for i in 0..n {
        for j in index.query(&signatures[i]) {
            let j = j as usize;
            if j <= i {
                continue; // each unordered pair considered once
            }
            let sim =
                frensense_engine::minhash::signature_similarity(&signatures[i], &signatures[j]);
            if sim >= similarity_threshold {
                uf.union(i, j);
            }
        }
    }

    // Group by root
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let root = uf.find(i);
        groups.entry(root).or_default().push(i);
    }

    // Build clusters
    let mut clusters = Vec::new();
    let mut cluster_id = 0;

    for (_root, members) in groups {
        if members.len() < 2 {
            continue; // Skip singletons
        }

        let cluster_members: Vec<ClusterMember> = members
            .iter()
            .map(|&idx| {
                let fp = &fingerprints[idx];
                let role = classify_member_role(fp, fingerprints, &signatures, idx, &members);
                ClusterMember {
                    fingerprint: fp.clone(),
                    cluster_role: role,
                }
            })
            .collect();

        let has_inconsistency = cluster_members
            .iter()
            .any(|m| m.cluster_role == ClusterRole::Inconsistent);

        clusters.push(FunctionCluster {
            id: cluster_id,
            members: cluster_members,
            has_inconsistency,
        });

        cluster_id += 1;
    }

    clusters
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Classify a function's role within its cluster.
fn classify_member_role(
    fp: &FunctionFingerprint,
    all_fps: &[FunctionFingerprint],
    signatures: &[Vec<u64>],
    self_idx: usize,
    cluster_indices: &[usize],
) -> ClusterRole {
    let has_category = |cat: &str| {
        let mut h = rustc_hash::FxHasher::default();
        std::hash::Hash::hash(cat, &mut h);
        let hash = std::hash::Hasher::finish(&h);
        fp.semantic_markers.binary_search(&hash).is_ok()
    };

    // Check if this function has validation/sanitization patterns structurally
    let has_validation = has_category("sanitize") || has_category("auth_middleware");

    // Check if this function has dangerous patterns structurally
    let has_danger = has_category("cmd_exec")
        || has_category("code_eval")
        || has_category("db_query")
        || has_category("db_write")
        || has_category("dom_xss");

    if has_validation && !has_danger {
        ClusterRole::Safe
    } else if has_danger && !has_validation {
        ClusterRole::Unsafe
    } else {
        // Guard against NaN on singleton clusters (Bug A)
        if cluster_indices.len() <= 1 {
            return ClusterRole::Consistent;
        }

        // Check if this member differs significantly from others in the cluster
        let self_name = &fp.function_name;
        let avg_sim: f64 = cluster_indices
            .iter()
            .filter(|&&other_idx| {
                let other_name = &all_fps[other_idx].function_name;
                other_name != self_name
            })
            .map(|&other_idx| {
                frensense_engine::minhash::signature_similarity(
                    &signatures[self_idx],
                    &signatures[other_idx],
                )
            })
            .sum::<f64>()
            / (cluster_indices.len().saturating_sub(1)) as f64;

        if avg_sim < 0.85 {
            ClusterRole::Inconsistent
        } else {
            ClusterRole::Consistent
        }
    }
}

/// Generate advisories from clusters with inconsistencies.
#[must_use]
pub fn cluster_to_advisories(clusters: &[FunctionCluster]) -> Vec<crate::Advisory> {
    let mut advisories = Vec::new();

    for cluster in clusters {
        if !cluster.has_inconsistency {
            continue;
        }

        let inconsistent: Vec<&ClusterMember> = cluster
            .members
            .iter()
            .filter(|m| m.cluster_role == ClusterRole::Inconsistent)
            .collect();

        let safe: Vec<&ClusterMember> = cluster
            .members
            .iter()
            .filter(|m| m.cluster_role == ClusterRole::Safe)
            .collect();

        for member in &inconsistent {
            let safe_names: Vec<&str> = safe
                .iter()
                .map(|m| m.fingerprint.function_name.as_str())
                .collect();

            let advisory = crate::Advisory::bare(
                "NEAR_DUPLICATE_INCONSISTENT",
                crate::Severity::Warning,
                crate::FileId(0),
                std::path::Path::new(&member.fingerprint.file_path),
                format!(
                    "Function '{}' is structurally similar to other functions in cluster {} but differs in implementation.{}",
                    member.fingerprint.function_name,
                    cluster.id,
                    if safe_names.is_empty() {
                        String::new()
                    } else {
                        format!(" Safe versions exist: {}", safe_names.join(", "))
                    }
                ),
            )
            .with_confidence(0.7)
            .with_line(u32::try_from(member.fingerprint.line).unwrap_or(u32::MAX))
            .with_content(member.fingerprint.function_name.clone())
            .with_impact("Inconsistent implementations of the same logic may indicate a missing security fix in one copy.")
            .with_improvement("Ensure all copies apply the same validation/sanitization. Consider extracting shared logic.")
            .with_tags(["consistency", "duplicate", "cluster"]);

            advisories.push(advisory);
        }
    }

    advisories
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_union_find() {
        let mut uf = UnionFind::new(5);
        uf.union(0, 1);
        uf.union(2, 3);
        assert_eq!(uf.find(0), uf.find(1));
        assert_eq!(uf.find(2), uf.find(3));
        assert_ne!(uf.find(0), uf.find(2));
    }

    fn make_fp(name: &str, body: &str) -> FunctionFingerprint {
        let source = format!("fn {name}() {{ {body} }}");
        let mut parser = tree_sitter::Parser::new();
        assert!(
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .is_ok()
        );
        let tree = parser.parse(&source, None).unwrap();
        let mut fps = Vec::new();
        frensense_engine::fingerprint::extract_fingerprints(
            tree.root_node(),
            &source,
            std::path::Path::new("test.rs"),
            &mut fps,
            5,
            None,
        );
        assert!(!fps.is_empty(), "no fingerprint for {source}");
        fps.remove(0)
    }

    #[test]
    fn test_cluster_functions_with_lsh() {
        // Identical (duplicated) functions share the same ngram set.
        let fps = vec![
            make_fp("dup_a", "read_to_string(path)?; let x = parse(&s); x.len()"),
            make_fp("dup_b", "read_to_string(path)?; let x = parse(&s); x.len()"),
            make_fp("dup_c", "read_to_string(path)?; let x = parse(&s); x.len()"),
            make_fp("unique_x", "a + b * c - d / e % f"),
            make_fp("unique_y", "g * h + i - j / k % l"),
        ];

        let clusters = cluster_functions(&fps, 0.75);

        // The three identical functions should land in one cluster of size 3.
        let triple = clusters
            .iter()
            .filter(|c| c.members.len() == 3)
            .collect::<Vec<_>>();
        assert_eq!(
            triple.len(),
            1,
            "expected one triple cluster, got {clusters:#?}"
        );
        assert!(!triple[0].has_inconsistency);
    }
}
