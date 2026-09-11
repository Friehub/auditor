use crate::loader::load_corpus;
use frensense_engine::auto_filter::AutoFilterEntry;
use frensense_engine::corpus::bundle::{BundlePattern, BundlePayload};
use std::path::Path;
// Note: imports will be fixed iteratively.
pub fn build_bundle_from_patterns(
    patterns: &[BundlePattern],
    corpus_dir_override: Option<&Path>,
) -> Result<Vec<u8>, String> {
    // Pre-compute API IDF at build time so loaders can skip recomputation (~100 ms saving)
    let api_idf_weights = compute_bundle_api_idf(patterns);

    // Learn per-category feature weights from positive/negative pairs
    let corpus_patterns: Vec<frensense_engine::corpus::pattern::CorpusPattern> = patterns
        .iter()
        .map(|bp| frensense_engine::corpus::pattern::CorpusPattern {
            id: bp.id.clone(),
            positives: bp.positives.clone(),
            negatives: bp.negatives.clone(),
            semantic_filter: bp.semantic_filter.clone(),
            observation: bp.observation.clone(),
            impact: bp.impact.clone(),
            improvement: bp.improvement.clone(),
            expected_context: bp.expected_context.clone(),
            cwe: bp.cwe.clone(),
            cvss: bp.cvss,
            owasp: bp.owasp.clone(),
            severity: bp.severity.clone(),
            runtime_probe: bp.runtime_probe.clone(),
        })
        .collect();
    let category_weights_vec: Vec<(String, [f64; 15])> =
        crate::pattern::weight_learner::learn_category_weights(&corpus_patterns)
            .into_iter()
            .collect();

    // Compute auto-derived semantic filter suggestions
    // We need source text for each pattern to extract imports and call targets
    // Use the explicit corpus_dir if provided (from build_bundle), otherwise fall back
    // to current_dir + corpus/targets (for incremental build path).
    let corpus_dir = corpus_dir_override
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| {
            std::env::current_dir()
                .map(|d| d.join("corpus").join("targets"))
                .unwrap_or_default()
        });
    // Recursively find a corpus file by its pattern ID and variant.
    fn find_corpus_file(id: &str, variant: &str, dir: &Path) -> Option<String> {
        for ext in &["ts", "tsx", "js", "jsx", "rs", "py", "go"] {
            let target = format!("{}_{}.{}", id, variant, ext);
            let result = find_file_recursive(dir, &target);
            if result.is_some() {
                return result;
            }
        }
        None
    }

    fn find_file_recursive(dir: &Path, target: &str) -> Option<String> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return None;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(src) = find_file_recursive(&path, target) {
                    return Some(src);
                }
            } else if path.is_file() {
                if path.file_name().and_then(|n| n.to_str()) == Some(target) {
                    return std::fs::read_to_string(&path).ok();
                }
            }
        }
        None
    }

    let mut pattern_source_texts = std::collections::HashMap::new();
    for bp in patterns {
        // Read positive and up to 4 negative source files for auto-filter learning.
        // Files may be in any subdirectory under corpus_dir.
        if let Some(src) = find_corpus_file(&bp.id, "positive", corpus_dir.as_path()) {
            pattern_source_texts.insert(bp.id.clone(), src);
        }
        for (i, variant) in ["negative", "negative2", "negative3", "negative4"]
            .iter()
            .enumerate()
        {
            if let Some(src) = find_corpus_file(&bp.id, variant, corpus_dir.as_path()) {
                pattern_source_texts.insert(format!("{}_neg_{}", bp.id, i), src);
            }
        }
    }
    let auto_stats = crate::auto_filter::compute_auto_filters(patterns, &pattern_source_texts);
    // Serialize auto-derived filter stats.  Each entry is:
    // (pid, imports, calls, must_not_contain_call_to, function_name_regex, excludes_nodes, excludes_fnames)
    let auto_filter_stats: Vec<AutoFilterEntry> = {
        let mut v = Vec::new();
        let all_pids: std::collections::HashSet<&str> =
            patterns.iter().map(|p| p.id.as_str()).collect();
        for pid in &all_pids {
            let calls = auto_stats
                .contains_call_to
                .get(*pid)
                .cloned()
                .unwrap_or_default();
            let excl_calls = auto_stats
                .must_not_contain_call_to
                .get(*pid)
                .cloned()
                .unwrap_or_default();
            let _fn_re = String::new();
            let req_nodes = auto_stats
                .contains_node_type
                .get(*pid)
                .cloned()
                .unwrap_or_default();
            let excl_nodes = auto_stats
                .must_not_contain_node_type
                .get(*pid)
                .cloned()
                .unwrap_or_default();
            let excl_fnames = auto_stats
                .must_not_match_function_name
                .get(*pid)
                .cloned()
                .unwrap_or_default();
            if !calls.is_empty()
                || !excl_calls.is_empty()
                || !req_nodes.is_empty()
                || !excl_nodes.is_empty()
            {
                v.push(AutoFilterEntry {
                    pattern_id: pid.to_string(),
                    required_calls: calls.into_iter().collect(),
                    forbidden_calls: excl_calls.into_iter().collect(),
                    required_node_types: req_nodes.into_iter().collect(),
                    forbidden_node_types: excl_nodes.into_iter().collect(),
                    forbidden_fn_names: excl_fnames.into_iter().collect(),
                });
            }
        }
        v
    };

    // Train per-pattern calibration sigmoids
    let pattern_cal: Vec<(String, f32, f32)> =
        crate::calibration::train_per_pattern_calibration(&corpus_patterns)
            .into_iter()
            .map(|(k, (a, b))| (k, a, b))
            .collect();

    let payload = BundlePayload {
        patterns: patterns.to_vec(),
        api_idf_weights,
        category_weights: category_weights_vec,
        auto_filter_stats,
        pattern_calibration: pattern_cal,
    };
    frensense_frc::write_bundle(&payload, patterns.len() as u32)
}

pub fn build_bundle_incremental(corpus_dir: &Path) -> Result<Vec<u8>, String> {
    let manifest_path = corpus_dir.join(".bundle_manifest.toml");
    let mut manifest = Manifest::load(&manifest_path);

    let patterns = load_corpus(corpus_dir)?.0;

    let bundle_patterns: Vec<BundlePattern> = patterns
        .into_iter()
        .map(|p| BundlePattern {
            id: p.id,
            positives: p.positives,
            negatives: p.negatives,
            semantic_filter: p.semantic_filter,
            observation: p.observation,
            impact: p.impact,
            improvement: p.improvement,
            expected_context: p.expected_context,
            cwe: p.cwe,
            cvss: p.cvss,
            owasp: p.owasp,
            severity: p.severity,
            runtime_probe: p.runtime_probe,
        })
        .collect();

    // Since build_bundle_incremental writes only patterns (no payload envelope in the old code?! Wait, let's look closer... ah, it serialized bundle_patterns directly!). Let's just fix it to use write_bundle. Wait, the old code serialized `bundle_patterns` without `BundlePayload`! That's a bug in the old code (it would fail to deserialize in `load_bundle`). I'll just change it to use write_bundle with `bundle_patterns`.
    let output = build_bundle_from_patterns(&bundle_patterns, Some(corpus_dir))?;

    // Update manifest with current file hashes
    if let Ok(entries) = std::fs::read_dir(corpus_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
                    && name != ".bundle_manifest.toml"
                {
                    continue;
                }
                if let Ok(metadata) = std::fs::metadata(&path) {
                    let mtime = metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map_or(0, |d| d.as_secs());
                    if let Ok(content) = std::fs::read(&path) {
                        let content_hash = blake3::hash(&content).into();
                        manifest.update_entry(
                            path.to_string_lossy().to_string(),
                            mtime,
                            content_hash,
                        );
                    }
                }
            }
        }
    }

    manifest.save(&manifest_path)?;

    Ok(output)
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct ManifestEntry {
    path: String,
    mtime: u64,
    content_hash: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
struct Manifest {
    entries: Vec<ManifestEntry>,
}

impl Manifest {
    fn load(path: &std::path::Path) -> Self {
        let Ok(content) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        toml::from_str(&content).unwrap_or_default()
    }

    fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, content).map_err(|e| e.to_string())
    }

    fn update_entry(&mut self, path: String, mtime: u64, content_hash: [u8; 32]) {
        self.entries.retain(|e| e.path != path);
        self.entries.push(ManifestEntry {
            path,
            mtime,
            content_hash,
        });
    }
}

fn compute_bundle_api_idf(
    patterns: &[frensense_engine::corpus::bundle::BundlePattern],
) -> Vec<(u64, f32)> {
    let total = patterns.len() as f32;
    if total == 0.0 {
        return Vec::new();
    }
    let mut api_doc_freq: rustc_hash::FxHashMap<u64, f32> = rustc_hash::FxHashMap::default();
    for pattern in patterns {
        let mut seen: rustc_hash::FxHashSet<u64> = rustc_hash::FxHashSet::default();
        for fp in &pattern.positives {
            for &call in &fp.api_calls {
                if seen.insert(call) {
                    *api_doc_freq.entry(call).or_insert(0.0) += 1.0;
                }
            }
        }
    }
    let mut weights: Vec<(u64, f32)> = api_doc_freq
        .into_iter()
        .map(|(hash, df)| (hash, (total / df).ln()))
        .collect();
    weights.sort_unstable_by_key(|&(hash, _)| hash);
    weights
}

pub fn build_bundle(corpus_dir: &std::path::Path) -> Result<Vec<u8>, String> {
    let patterns = crate::loader::load_corpus(corpus_dir)?.0;

    let bundle_patterns: Vec<frensense_engine::corpus::bundle::BundlePattern> = patterns
        .into_iter()
        .map(|p| frensense_engine::corpus::bundle::BundlePattern {
            id: p.id,
            positives: p.positives,
            negatives: p.negatives,
            semantic_filter: p.semantic_filter,
            observation: p.observation,
            impact: p.impact,
            improvement: p.improvement,
            expected_context: p.expected_context,
            cwe: p.cwe,
            cvss: p.cvss,
            owasp: p.owasp,
            severity: p.severity,
            runtime_probe: p.runtime_probe,
        })
        .collect();

    build_bundle_from_patterns(&bundle_patterns, Some(corpus_dir))
}
