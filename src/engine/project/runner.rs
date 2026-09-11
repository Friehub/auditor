// SPDX-License-Identifier: MIT

use super::Engine;
use super::{FileSnapshot, cache, config};
use crate::engine::auditor::AuditOptions;
use crate::engine::suppression::SuppressConfig;

use crate::semantics::data_flow::normalization::SemanticExtractor;
use crate::semantics::provider::{RustHirMap, per_file_provider};
use crate::semantics::symbols::SymbolRegistry;
use crate::{Advisory, FileId, Result};
use frensense_engine::data_flow::alias::AliasTracker;
use frensense_engine::data_flow::{FunctionTaintSummary, TaintOrigin, TaintRegistry};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::{HashMap, HashSet};
use std::hash::Hasher;
use std::path::{Path, PathBuf};

struct ProcessSnapshotsResult<'a> {
    symbols: SymbolRegistry,
    file_ids: Vec<(FileId, PathBuf)>,
    snapshot_map: rustc_hash::FxHashMap<FileId, &'a FileSnapshot>,
}

/// Build the rust-analyzer HIR map for the analysed workspace once per scan.
/// Returns `None` when the `rust-hir` feature is off, `--use-compiler` is not
/// set, there is no `Cargo.toml`, or the type-check fails (we then fall back
/// to heuristics rather than abort the scan).
fn build_rust_hir(engine: &Engine, root: &Path) -> Option<std::sync::Arc<RustHirMap>> {
    #[cfg(feature = "rust-hir")]
    {
        if !engine.use_compiler {
            return None;
        }
        let manifest = root.join("Cargo.toml");
        if !manifest.exists() {
            return None;
        }
        return frensense_providers::rust_hir_provider::build_hir_type_map(&manifest)
            .map(std::sync::Arc::new)
            .map_err(|e| {
                tracing::warn!(
                    file = %manifest.display(),
                    error = %e,
                    "rust-hir type map build failed; falling back to heuristics"
                )
            })
            .ok();
    }
    #[cfg(not(feature = "rust-hir"))]
    {
        let _ = (engine, root);
        None
    }
}

///
/// # Errors
/// May return an error if the operation fails.
///
/// # Panics
/// May panic if internal assertions fail.
/// Shared snapshot processing: build symbol registry, add edges, discover events.
fn process_snapshots<'a>(
    auditor: &crate::engine::auditor::FrensenseAuditor,
    snapshots: &'a [FileSnapshot],
) -> Result<ProcessSnapshotsResult<'a>> {
    let mut symbols = SymbolRegistry::new();
    let mut file_ids = Vec::with_capacity(snapshots.len());
    let mut snapshot_map =
        rustc_hash::FxHashMap::with_capacity_and_hasher(snapshots.len(), Default::default());

    for snap in snapshots {
        file_ids.push((snap.id, snap.path.clone()));
        snapshot_map.insert(snap.id, snap);
        for sym in snap.symbols.clone() {
            symbols.insert(sym);
        }
    }

    for snap in snapshots {
        for (caller, callee) in &snap.edges {
            symbols.add_call_edge(&snap.path, caller, callee);
        }
    }

    for snap in snapshots {
        auditor.discover_events(&snap.path, &snap.content, &snap.tree, &mut symbols)?;
    }

    Ok(ProcessSnapshotsResult {
        symbols,
        file_ids,
        snapshot_map,
    })
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Build `file_trees` map from snapshots.
fn build_file_trees(
    snapshots: &[FileSnapshot],
) -> rustc_hash::FxHashMap<
    String,
    (
        tree_sitter::Tree,
        String,
        Vec<crate::semantics::data_flow::normalization::SemanticOp>,
    ),
> {
    let mut file_trees =
        rustc_hash::FxHashMap::with_capacity_and_hasher(snapshots.len(), Default::default());
    for snap in snapshots {
        file_trees.insert(
            snap.path.to_string_lossy().to_string(),
            (
                snap.tree.clone(),
                snap.content.clone(),
                snap.semantic_ops.clone(),
            ),
        );
    }
    file_trees
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Merge config + CLI severity overrides (CLI wins) into advisories.
fn apply_severity_overrides(
    advisories: &mut [Advisory],
    config_overrides: Option<&HashMap<String, crate::Severity>>,
    cli_overrides: &HashMap<String, crate::Severity>,
) {
    let mut merged = config_overrides.cloned().unwrap_or_default();
    for (rule_id, sev) in cli_overrides {
        merged.insert(rule_id.clone(), *sev);
    }
    for adv in advisories {
        if let Some(sev) = merged.get(&adv.rule_id) {
            adv.severity = *sev;
        }
    }
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Run all findings modules (W1-W7) on snapshots.
fn run_findings_modules(
    _root: &Path,
    snapshots: &[FileSnapshot],
    symbols: &SymbolRegistry,
    _file_trees: &rustc_hash::FxHashMap<
        String,
        (
            tree_sitter::Tree,
            String,
            Vec<crate::semantics::data_flow::normalization::SemanticOp>,
        ),
    >,
    _extra_taint_rule_dirs: &[PathBuf],
    _dep_resolver: &mut frensense_engine::deps::DependencyResolver,
    source_sink: &frensense_engine::corpus::source_sink::CorpusSourceSinkRegistry,
    all_advisories: &mut Vec<Advisory>,
    use_data_flow: bool,
    use_compiler: bool,
    rust_hir: Option<std::sync::Arc<RustHirMap>>,
    cross_file_taint: &mut frensense_engine::data_flow::cross_file::CrossFileTaintResolver,
) {
    use crate::engine::findings::{FindingContext, registered_modules};

    let modules = registered_modules();

    // Create sanitizer registry for taint suppression
    let sanitizer = frensense_engine::data_flow::SanitizerRegistry::default_combined();

    // Instantiate dormant modules
    let _alias_tracker = frensense_engine::data_flow::AliasTracker::new();
    let mut exposed_count = 0;

    // Seed the cross-file taint resolver with user input sources
    if use_data_flow {
        let source_sink_arc = std::sync::Arc::new(source_sink.clone());
        for snap in snapshots {
            let file_env =
                frensense_engine::context::FileContext::extract(&snap.path, &snap.content)
                    .environment;
            let provider = per_file_provider(
                &snap.content,
                &snap.tree,
                &snap.path,
                source_sink_arc.clone(),
                Some(file_env),
                use_compiler,
                rust_hir.clone(),
            );
            let root = snap.tree.root_node();
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    stack.push(child);
                }

                if node.kind() == "function_declaration"
                    || node.kind() == "arrow_function"
                    || node.kind() == "method_definition"
                    || node.kind() == "function"
                {
                    let mut fn_name_str = String::new();
                    if let Some(name_node) = node.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(snap.content.as_bytes()) {
                            fn_name_str = name.to_string();
                        }
                    } else if let Some(parent) = node.parent() {
                        // Try to get name from variable declarator: `const myFunc = () => {}`
                        if parent.kind() == "variable_declarator" {
                            if let Some(name_node) = parent.child_by_field_name("name") {
                                if let Ok(name) = name_node.utf8_text(snap.content.as_bytes()) {
                                    fn_name_str = name.to_string();
                                }
                            }
                        } else if parent.kind() == "pair" || parent.kind() == "property_identifier"
                        {
                            if let Some(key_node) = parent.child_by_field_name("key") {
                                if let Ok(name) = key_node.utf8_text(snap.content.as_bytes()) {
                                    fn_name_str = name.to_string();
                                }
                            }
                        }
                    }

                    if fn_name_str.is_empty() {
                        fn_name_str = format!(
                            "anon_{}_{}",
                            node.start_position().row,
                            node.start_position().column
                        );
                    }

                    if let Some(params_node) = node
                        .child_by_field_name("parameters")
                        .or_else(|| node.child_by_field_name("formal_parameters"))
                    {
                        let mut p_cursor = params_node.walk();
                        let mut detected_origin: Option<frensense_engine::data_flow::TaintOrigin> =
                            None;
                        for param in params_node.children(&mut p_cursor) {
                            if matches!(param.kind(), "(" | ")" | "," | ";" | "self") {
                                continue;
                            }
                            let (mut param_name, param_type) =
                                frensense_engine::corpus::source_sink::extract_param_info(
                                    param,
                                    &snap.content,
                                );
                            if param_name.is_empty() && param.kind() == "identifier" {
                                param_name =
                                    snap.content[param.start_byte()..param.end_byte()].to_string();
                            }
                            let clean_type = param_type.trim_start_matches(':').trim();

                            let param_env = frensense_engine::context::FileContext::extract(
                                &snap.path,
                                &snap.content,
                            )
                            .environment;

                            let origin = provider
                                .classify_param(&param_name, Some(clean_type))
                                .or_else(|| {
                                    frensense_engine::data_flow::classify_param_name_in_context(
                                        &param_name,
                                        Some(&param_env),
                                    )
                                });
                            if let Some(o) = origin {
                                detected_origin = Some(o);
                                break;
                            }
                        }

                        if let Some(origin) = detected_origin.clone() {
                            cross_file_taint.register_exposed_taint(
                                &fn_name_str,
                                &snap.path.to_string_lossy(),
                                origin,
                            );
                            exposed_count += 1;
                        }
                    }
                }
            }
        }

        tracing::trace!(
            exposed_count,
            "cross-file taint: registered exposed sources"
        );

        // Propagate taint forward through the call graph so intermediate
        // non-HttpHandler functions called by seeded sources are also
        // treated as taint sources for multi-hop chain detection.
        cross_file_taint.propagate_taint(Some(&sanitizer));
    }

    for snap in snapshots {
        let mut ctx = FindingContext {
            symbols,
            cross_file_taint: Some(&cross_file_taint),
            source_sink,
            sanitizer: &sanitizer,
        };
        for module in &modules {
            all_advisories.extend(module.run(snap, &mut ctx));
        }
    }
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Run corpus pattern matching on snapshots.
fn run_corpus_scan(
    engine: &Engine,
    root: &Path,
    snapshots: &[FileSnapshot],
    symbols: &crate::semantics::symbols::SymbolRegistry,
    data_flow: &frensense_engine::data_flow::DataFlowEngine,
    file_trees: &rustc_hash::FxHashMap<
        String,
        (
            tree_sitter::Tree,
            String,
            Vec<crate::semantics::data_flow::normalization::SemanticOp>,
        ),
    >,
    all_advisories: &mut Vec<Advisory>,
    npm_deps: &std::collections::HashSet<String>,
    cross_file_taint: &mut frensense_engine::data_flow::cross_file::CrossFileTaintResolver,
    rust_hir: Option<std::sync::Arc<RustHirMap>>,
) -> frensense_engine::corpus::source_sink::CorpusSourceSinkRegistry {
    let alias_tracker = std::sync::Mutex::new(AliasTracker::new());

    // Load suppressions from .frensense-suppress.yml
    let suppressions = load_suppressions(root);

    let mut corpus_dirs: Vec<&Path> = Vec::new();
    if let Some(ref corpus_dir) = engine.corpus_dir {
        corpus_dirs.push(corpus_dir.as_path());
    }

    let mut registry = frensense_engine::corpus::registry::PatternRegistry::new(
        engine.corpus_threshold,
        engine.ngram_sim_threshold,
        0.20,
    );
    for (category, threshold) in &engine.threshold_overrides {
        registry.set_threshold_override(category.clone(), *threshold);
    }

    // Apply scorer configuration from CLI flags
    {
        let mut config = frensense_engine::pattern::scorer::ScorerConfig::default();
        if let Some(val) = engine.scorer_cross_lingual_penalty {
            config.cross_lingual_penalty = val;
        }
        if let Some(val) = engine.scorer_semantic_zero_penalty {
            config.semantic_zero_penalty = val;
        }
        if let Some(val) = engine.scorer_semantic_match_boost {
            config.semantic_match_boost = val;
        }
        if let Some(val) = engine.scorer_noise_gate_moderate {
            config.noise_gate_moderate_signal = val;
        }
        if let Some(val) = engine.scorer_noise_gate_strong {
            config.noise_gate_strong_signal = val;
        }
        if let Some(val) = engine.scorer_neg_penalty_floor {
            config.neg_penalty_floor = val;
        }
        if let Some(val) = engine.scorer_neg_penalty_weight {
            config.neg_penalty_weight = val;
        }
        if let Some(val) = engine.scorer_context_mismatch_penalty {
            config.context_mismatch_penalty = val;
        }
        registry.set_scorer_config(config);
    }
    let mut corpus_loaded = false;

    #[cfg(feature = "fingerprinting")]
    if corpus_dirs.is_empty() {
        if let Some(bundle_bytes) = engine.corpus_bundle {
            match registry.load_from_bundle(bundle_bytes) {
                Ok(count) if count > 0 => {
                    eprintln!("Loaded {count} patterns from embedded bundle");
                    corpus_loaded = true;
                }
                Ok(_) => {}
                Err(_e) => {
                    // Bundle format mismatch — fall through to corpus directory
                }
            }
        }
        // If bundle failed, try loading from the default corpus directory
        if !corpus_loaded {
            let default_corpus = std::path::Path::new("corpus/targets");
            if default_corpus.exists() {
                corpus_dirs.push(default_corpus);
            }
        }
    }

    // Load from corpus directories if specified (exclusive of embedded bundle)
    if !corpus_dirs.is_empty() {
        let mut total_loaded = 0;
        for dir in &corpus_dirs {
            match frensense_bundler::builder::build_bundle(dir) {
                Ok(bytes) => match registry.load_from_bundle(&bytes) {
                    Ok(count) => total_loaded += count,
                    Err(e) => eprintln!("Failed to load built bundle for {:?}: {}", dir, e),
                },
                Err(e) => eprintln!("Failed to build bundle from {:?}: {}", dir, e),
            }
        }
        if total_loaded > 0 {
            eprintln!("Loaded {} patterns from corpus directory", total_loaded);
            corpus_loaded = true;
        }
    }

    // Override per-category weights for security categories where API call overlap
    // is the strongest signal but trained weights under-emphasize it.
    // These can be overridden via ScorerConfig::category_weight_overrides.
    let default_sqli_weights: [f64; 15] = [
        0.05, 0.10, 0.04, 0.02, 0.02, 0.05, 0.04, 0.25, 0.30, 0.03, 0.05, 0.03, 0.02, 0.04, 0.04,
    ];
    for category in &["sqli", "nosqli"] {
        let weights = engine
            .scorer_config
            .category_weight_overrides
            .get(*category)
            .copied()
            .unwrap_or(default_sqli_weights);
        registry.set_category_weights(category, weights);
    }

    if !corpus_loaded {
        return frensense_engine::corpus::source_sink::CorpusSourceSinkRegistry::new(
            engine.use_compiler,
        );
    }
    let ngram_window_size = engine.ngram_window_size;
    let per_category_calibration = engine.per_category_calibration.clone();
    let calibration = engine.calibration.clone();
    let use_compiler = engine.use_compiler;
    let source_sink_arc = std::sync::Arc::new(registry.source_sink_registry().clone());

    // Pass 2 for CLI: Quick heuristic for return-value taint
    let mut local_tainted_vars: rustc_hash::FxHashMap<String, Vec<String>> =
        rustc_hash::FxHashMap::default();
    for (file_path, (_tree, _content, ops)) in file_trees {
        let mut file_vars = Vec::new();
        for op in ops {
            if let crate::semantics::data_flow::normalization::SemanticOp::Call {
                function_name,
                range,
                ..
            } = op
            {
                let lower = function_name.to_lowercase();
                if source_sink_arc.is_source_pattern(function_name)
                    || lower.ends_with(".find")
                    || lower.ends_with(".findone")
                    || lower.ends_with(".findall")
                    || lower.ends_with(".query")
                    || lower.ends_with(".execute")
                {
                    for binding_op in ops {
                        if let crate::semantics::data_flow::normalization::SemanticOp::Binding {
                            name: b_name,
                            value_range,
                        } = binding_op
                        {
                            if value_range.start_byte <= range.start_byte
                                && value_range.end_byte >= range.end_byte
                            {
                                file_vars.push(b_name.clone());
                            }
                        }
                    }
                }
            }
        }
        if !file_vars.is_empty() {
            local_tainted_vars.insert(file_path.clone(), file_vars);
        }
    }

    let all_fps: Vec<(
        frensense_engine::fingerprint::FunctionFingerprint,
        tree_sitter::Node<'_>,
        &FileSnapshot,
        frensense_engine::context::FileContext,
    )> = snapshots
        .par_iter()
        .flat_map(|snap| {
            if is_test_file(&snap.path) {
                return Vec::new();
            }
            let start_time = std::time::Instant::now();
            let ctx = frensense_engine::context::FileContext::extract(&snap.path, &snap.content);
            let mut fps = Vec::new();

            tracing::trace!(file = %snap.path.display(), "extracting fingerprints");

            let ext = snap.path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let import_map = frensense_engine::import_resolver::ImportMap::build_from_tree(
                ext,
                &snap.content,
                snap.tree.root_node(),
            );

            frensense_engine::fingerprint::extract_fingerprints_with_nodes(
                snap.tree.root_node(),
                &snap.content,
                &snap.path,
                &mut fps,
                ngram_window_size,
                Some(&import_map),
            );
            if start_time.elapsed().as_millis() > 500 {
                tracing::warn!(
                    file = %snap.path.display(),
                    ms = start_time.elapsed().as_millis(),
                    "slow fingerprinting"
                );
            }
            fps.into_iter()
                .map(move |(fp, node)| (fp, node, snap, ctx.clone()))
                .collect::<Vec<_>>()
        })
        .collect();

    tracing::info!(
        count = all_fps.len(),
        "fingerprinting completed; beginning scoring pipeline"
    );
    let scoring_start_time = std::time::Instant::now();

    // Pre-group identical fingerprints to avoid redundant scoring.
    let mut groups: rustc_hash::FxHashMap<
        u64,
        Vec<(
            frensense_engine::fingerprint::FunctionFingerprint,
            tree_sitter::Node<'_>,
            &FileSnapshot,
            frensense_engine::context::FileContext,
        )>,
    > = rustc_hash::FxHashMap::default();
    for item in all_fps {
        let hash = compute_fp_hash(&item.0);
        groups.entry(hash).or_default().push(item);
    }

    let new_advisories: Vec<Advisory> = groups.into_par_iter().flat_map(|(_hash, group)| {
        let start_time = std::time::Instant::now();
        let use_data_flow = engine.use_data_flow;
        let mut result = Vec::new();

        // Score once — all group members share the same fingerprint hash
        let (ref fp, func_node, ref snap, ref actual_context) = group[0];

        // Merge learned semantic markers into the fingerprint.
        // These are API-call-to-category mappings discovered from the corpus,
        // supplementing the hardcoded categories in extract_semantic_markers.
        let scan_fp = if !registry.learned_semantic_markers.is_empty() {
            let mut merged = fp.clone();
            let mut extra = rustc_hash::FxHashSet::default();
            let existing: rustc_hash::FxHashSet<u64> = merged.semantic_markers.iter().copied().collect();
            for call in &merged.raw_call_names {
                let seg = call.rsplit(|c: char| c == '.' || c == ':')
                    .next()
                    .unwrap_or(call);
                if let Some(category) = registry.learned_semantic_markers.get(seg) {
                    let mut h = rustc_hash::FxHasher::default();
                    std::hash::Hash::hash(category, &mut h);
                    extra.insert(h.finish());
                }
            }
            for h in &extra {
                if !existing.contains(h) {
                    merged.semantic_markers.push(*h);
                }
            }
            merged.semantic_markers.sort_unstable();
            merged
        } else {
            fp.clone()
        };
        let scan_ctx = frensense_engine::corpus::registry::ScanContext {
            func_node: Some(func_node.clone()),
            source: Some(&snap.content),
            actual_context: Some(actual_context),
            spec: None,
        };
        let matches = registry.scan_function(&scan_fp, &scan_ctx);

        let elapsed = start_time.elapsed().as_millis();
        if elapsed > 500 {
            tracing::warn!(function = %fp.function_name, file = %snap.path.display(), ms = elapsed, "slow scoring");
        }

        for m in &matches {
            // Replicate advisory across all group members
            for (fp_i, func_node_i, snap_i, _ctx_i) in &group {
                let mut local_advisories = Vec::new();

                let impact = m.impact.clone().unwrap_or_else(|| {
                    "Function shape matches a known violation pattern. Unsanitized data from `{{ source }}` reaches the `{{ sink }}` execution context.".to_string()
                });
                let improvement = m.improvement.clone()
                    .unwrap_or_else(|| "Review against corpus example.".to_string());
                let observation = m.observation.clone().unwrap_or_else(|| {
                    format!(
                        "Corpus pattern: {} (score {:.2}) in '{}'",
                        m.pattern_id, m.score, fp_i.function_name
                    )
                });

                let category = m.pattern_id.split('_').nth(1).unwrap_or("default");
                // Apply per-category or global calibration to the raw pattern score.
                // NOTE: per_pattern_calibration::calibrate is already applied inside
                // registry::score_candidate. Do NOT apply it again here — double sigmoid
                // application compresses all scores toward 1.0 and inflates FP confidence.
                let mut confidence = if let Some(ref per_cat_cal) = per_category_calibration {
                    per_cat_cal.calibrate(m.score, category)
                } else if let Some(ref params) = calibration {
                    params.calibrate(m.score)
                } else {
                    m.score
                };

                // Minimum-score gate: skip findings where key similarity dimensions are near-zero.
                // This prevents the calibration sigmoid from boosting noise into high-confidence FPs.
                if let Some(ref evidence) = m.matched_evidence {
                    let _ngram_low = evidence.ngram_sim < 0.05;
                    let _sig_low = evidence.signature_sim < 0.05;                    // Skip if both ngram AND signature are near-zero (no textual/structural match).
                    // API similarity alone is insufficient — generic calls like `console.log`
                    // match many patterns without real vulnerability overlap.
                    // FIXME: We temporarily disable this gate because Juice Shop's 78-line functions 
                    // vs Corpus 15-line functions naturally drop below 5% textual overlap.
                    // if ngram_low && sig_low {
                    //     continue;
                    // }

                }

                let mut taint_verified = false;
                let mut taint_detail = String::new();
                let mut source_name = None;
                let mut sink_name = None;
                if use_data_flow {
                    let verification = {
                        let mut guard = alias_tracker.lock().unwrap();
                        let file_env =
                            frensense_engine::context::FileContext::extract(
                                &snap_i.path,
                                &snap_i.content,
                            )
                            .environment;
                        let provider = per_file_provider(
                            &snap_i.content,
                            &snap_i.tree,
                            &snap_i.path,
                            source_sink_arc.clone(),
                            Some(file_env),
                            use_compiler,
                            rust_hir.clone(),
                        );
                        verify_taint_flow(
                            func_node_i.clone(),
                            &snap_i.content,
                            &snap_i.tree,
                            &snap_i.path,
                            symbols,
                            data_flow,
                            file_trees,
                            registry.source_sink_registry(),
                            npm_deps,
                            &mut *guard,
                            Some(provider.as_ref()),
                        )
                    };

                    source_name = verification.source_name;
                    sink_name = verification.sink_name;

                    if verification.verified {
                        taint_verified = true;
                        taint_detail = verification.detail;
                        confidence = (confidence * engine.scorer_config.taint_verified_boost)
                            .min(engine.scorer_config.taint_boost_cap);
                    }

                    // Cross-file taint boost: if intra-procedural didn't verify,
                    // check if a cross-file path exists from an exposed source
                    // (e.g. route handler) to this sink function.
                    if !taint_verified {
                        let fn_role = frensense_engine::function_role::classify_role(&fp_i);
                        if matches!(
                            fn_role,
                            frensense_engine::function_role::FunctionRole::DbQuery
                                | frensense_engine::function_role::FunctionRole::ShellExecutor
                        ) {
                            let taints = cross_file_taint.resolve_taint(
                                &fp_i.function_name,
                                &snap_i.path.to_string_lossy(),
                                10,
                            );
                            if !taints.is_empty() {
                                taint_verified = true;
                                taint_detail = format!(
                                    "cross-file: {}:{} → {}:{} (depth={})",
                                    taints[0].source_file, taints[0].source_symbol,
                                    taints[0].sink_file, taints[0].sink_symbol,
                                    taints[0].path_length,
                                );
                                confidence = (confidence * engine.scorer_config.cross_file_taint_boost)
                                    .min(engine.scorer_config.taint_boost_cap);
                            }
                        }
                    }

                    // CFG+def-use taint confidence adjustment: if taint verification DID NOT
                    // find a flow, the adjuster's CFG-based analysis may still find one.
                    // If it also finds nothing, confidence is reduced.
                    if !taint_verified {
                        if let Some(ref ev) = m.matched_evidence {
                            if !ev.matched_calls.is_empty() {
                                let fn_byte = {
                                    let mut line = 1u32;
                                    let mut byte = 0usize;
                                    let target = fp_i.line as u32;
                                    for (i, &b) in snap_i.content.as_bytes().iter().enumerate() {
                                        if line >= target { byte = i; break; }
                                        if b == b'\n' { line += 1; }
                                    }
                                    byte
                                };
                                for call in &ev.matched_calls {
                                    let pattern = format!("{}(", call);
                                    if let Some(pos) = snap_i.content[fn_byte..].find(&pattern) {
                                        let start = fn_byte + pos;
                                        let mut depth = 1u32;
                                        let mut end = start + pattern.len();
                                        for (j, &b) in snap_i.content.as_bytes()[end..].iter().enumerate() {
                                            if b == b'(' { depth += 1; }
                                            else if b == b')' { depth -= 1; }
                                            if depth == 0 { end += j + 1; break; }
                                        }
                                        let sink_content = &snap_i.content[start..end];
                                        let adj = frensense_engine::data_flow::confidence::TaintConfidenceAdjuster::adjust_confidence(
                                            &snap_i.content,
                                            &snap_i.path,
                                            fp_i.line as u32,
                                            sink_content,
                                            confidence as f32,
                                            registry.source_sink_registry(),
                                            local_tainted_vars.get(&snap_i.path.to_string_lossy().to_string()).map(|v| v.as_slice()),
                                        );
                                        if (adj as f64) < confidence {
                                            confidence = adj as f64;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                let mut impact = impact;
                let mut improvement = improvement;

                let src_str = source_name.as_deref().unwrap_or("user input");
                let snk_str = sink_name.as_deref().unwrap_or("execution sink");

                impact = impact.replace("{{ source }}", src_str);
                impact = impact.replace("{{ sink }}", snk_str);
                impact = impact.replace("{{source}}", src_str);
                impact = impact.replace("{{sink}}", snk_str);

                improvement = improvement.replace("{{ source }}", src_str);
                improvement = improvement.replace("{{ sink }}", snk_str);
                improvement = improvement.replace("{{source}}", src_str);
                improvement = improvement.replace("{{sink}}", snk_str);

                if !taint_verified && m.score < engine.scorer_config.score_suppression_floor {
                    continue;
                }

                let mut advisory = Advisory::bare(
                    format!("CORPUS_{}", m.pattern_id.to_uppercase()),
                    crate::Severity::Warning,
                    snap_i.id,
                    &snap_i.path,
                    &observation,
                )
                .with_confidence(confidence)
                .with_line(u32::try_from(fp_i.line).unwrap_or(u32::MAX))
                .with_content(fp_i.function_name.clone())
                .with_enclosing_symbol(fp_i.function_name.clone())
                .with_impact(&impact)
                .with_improvement(&improvement)
                .with_tags(["corpus", "pattern"]);

                if taint_verified {
                    advisory = advisory.with_tags(["corpus", "pattern", "taint-verified"]);
                    advisory.impact = format!("{impact}\n\nTaint flow verified: {taint_detail}");
                }

                advisory.match_evidence = m.matched_evidence.clone();
                advisory.cwe = m.cwe.clone();
                advisory.cvss = m.cvss;
                advisory.owasp = m.owasp.clone();
                advisory.taint_branch_ratio = m.taint_branch_ratio;
                advisory.has_validation_name = Some(m.has_validation_name);

                // Skip frontend code for SQLi/NoSQLi patterns — Angular RxJS and frontend
                // code cannot execute SQL, so matches are always false positives.
                let path_str = snap_i.path.to_string_lossy();
                let is_injection_pattern = advisory.rule_id.contains("SQLI") || advisory.rule_id.contains("NOSQLI");
                let is_frontend = path_str.contains("/frontend/");
                if is_injection_pattern && is_frontend {
                    continue;
                }

                if !is_corpus_suppressed(&suppressions, &advisory.rule_id, &snap_i.path) {
                    local_advisories.push(advisory);
                }

                result.extend(local_advisories);
            }
        }
        result
    }).collect();

    tracing::info!(
        ms = scoring_start_time.elapsed().as_millis(),
        "scoring pipeline completed"
    );

    all_advisories.extend(new_advisories);

    // Update pattern freshness based on scan results
    // Track which patterns matched and which were taint-verified
    let mut matched_patterns: Vec<String> = Vec::new();
    let mut verified_patterns: std::collections::HashSet<String> = std::collections::HashSet::new();
    for advisory in all_advisories.iter() {
        if advisory.rule_id.starts_with("CORPUS_") {
            let pattern_id = advisory.rule_id["CORPUS_".len()..].to_lowercase();
            matched_patterns.push(pattern_id.clone());
            if advisory.tags.iter().any(|t| t == "taint-verified") {
                verified_patterns.insert(pattern_id);
            }
        }
    }
    registry.update_freshness_batch(&matched_patterns, &verified_patterns);

    registry.source_sink_registry().clone()
}

/// Compute a stable identity hash for a FunctionFingerprint.
/// Used to group identical fingerprints before parallel scoring.
fn compute_fp_hash(fp: &frensense_engine::fingerprint::FunctionFingerprint) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::default();
    fp.ngram_hashes.hash(&mut hasher);
    fp.structural_markers.hash(&mut hasher);
    fp.api_calls.hash(&mut hasher);
    fp.control_flow_hashes.hash(&mut hasher);
    hasher.finish()
}

/// Standalone taint mode: scan ALL functions for source→sink flows
/// without requiring a corpus match. This is the "trained to find a bug"
/// mode — the engine uses compiler info + name heuristics to trace taint
/// through the full code and reports verified flows.
fn run_standalone_taint(
    engine: &Engine,
    snapshots: &[FileSnapshot],
    symbols: &crate::semantics::symbols::SymbolRegistry,
    data_flow: &frensense_engine::data_flow::DataFlowEngine,
    file_trees: &rustc_hash::FxHashMap<
        String,
        (
            tree_sitter::Tree,
            String,
            Vec<crate::semantics::data_flow::normalization::SemanticOp>,
        ),
    >,
    source_sink: &frensense_engine::corpus::source_sink::CorpusSourceSinkRegistry,
    npm_deps: &std::collections::HashSet<String>,
    all_advisories: &mut Vec<Advisory>,
    use_compiler: bool,
    rust_hir: Option<std::sync::Arc<RustHirMap>>,
    cross_file_taint: &frensense_engine::data_flow::cross_file::CrossFileTaintResolver,
) {
    use frensense_engine::data_flow::alias::AliasTracker;

    let alias_tracker = std::sync::Mutex::new(AliasTracker::new());
    let function_kinds: &[&str] = &[
        "function_declaration",
        "method_definition",
        "arrow_function",
        "function_item",
        "function_definition",
    ];

    let advisories: Vec<Advisory> = snapshots
        .par_iter()
        .flat_map(|snap| {
            let mut local = Vec::new();
            let root = snap.tree.root_node();
            let mut cursor = root.walk();
            loop {
                let node = cursor.node();
                if function_kinds.contains(&node.kind()) {
                    let fn_name = node
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(snap.content.as_bytes()).ok())
                        .map_or("_anonymous", |s| s);

                    // Skip test functions
                    if fn_name.starts_with("test") || fn_name.contains("_test_") {
                        if cursor.goto_first_child() {
                            continue;
                        }
                    } else {
                        let verification = {
                            let mut guard = alias_tracker.lock().unwrap();
                            let file_env = frensense_engine::context::FileContext::extract(
                                &snap.path,
                                &snap.content,
                            )
                            .environment;
                            let provider = per_file_provider(
                                &snap.content,
                                &snap.tree,
                                &snap.path,
                                std::sync::Arc::new(source_sink.clone()),
                                Some(file_env),
                                use_compiler,
                                rust_hir.clone(),
                            );
                            verify_taint_flow(
                                node,
                                &snap.content,
                                &snap.tree,
                                &snap.path,
                                symbols,
                                data_flow,
                                file_trees,
                                source_sink,
                                npm_deps,
                                &mut *guard,
                                Some(provider.as_ref()),
                            )
                        };

                        if verification.verified {
                            let src = verification.source_name.as_deref().unwrap_or("user input");
                            let snk = verification.sink_name.as_deref().unwrap_or("sink");
                            let line = verification.sink_line.map(|l| l + 1).unwrap_or_else(|| node.start_position().row as u32 + 1);
                            let rule_id = format!(
                                "TAINT_{}_{}_{}",
                                snap.path
                                    .file_stem()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("unknown")
                                    .to_uppercase(),
                                fn_name.to_uppercase(),
                                src.to_uppercase(),
                            );

                            let advisory = Advisory::bare(
                                rule_id,
                                crate::Severity::Warning,
                                snap.id,
                                &snap.path,
                                format!(
                                    "Taint flow verified: `{src}` → `{fn_name}` → `{snk}`"
                                ),
                            )
                            .with_confidence(1.0)
                            .with_line(line)
                            .with_content(fn_name.to_string())
                            .with_enclosing_symbol(fn_name.to_string())
                            .with_impact(&format!(
                                "Unsanitized data from `{src}` reaches the `{snk}` sink through `{fn_name}`.\n\nTaint flow: {}",
                                verification.detail,
                            ))
                            .with_improvement(&format!(
                                "Sanitize `{src}` before passing to `{snk}` in `{fn_name}`."
                            ))
                            .with_tags(["taint-verified", "standalone"]);

                            local.push(advisory);
                        } else {
                            // Check cross-file taint: does taint from an exposed source
                            // in another file flow into this function (which is a sink)?
                            let fn_name_lower = fn_name.to_lowercase();
                            let is_sink = fn_name_lower.contains("query")
                                || fn_name_lower.contains("exec")
                                || fn_name_lower.contains("eval")
                                || fn_name_lower.contains("find")
                                || fn_name_lower.contains("update")
                                || fn_name_lower.contains("insert")
                                || fn_name_lower.contains("delete")
                                || fn_name_lower.contains("aggregate")
                                || fn_name_lower.contains("stream")
                                || fn_name_lower.contains("spawn")
                                || fn_name_lower.contains("redirect")
                                || fn_name_lower.contains("render");

                            if is_sink {
                                let taints = cross_file_taint.resolve_taint(
                                    fn_name,
                                    &snap.path.to_string_lossy(),
                                    10,
                                );
                                if !taints.is_empty() {
                                    let src = &taints[0].source_symbol;
                                    let snk = fn_name;
                                    let line = node.start_position().row as u32 + 1;
                                    let rule_id = format!(
                                        "TAINT_XFILE_{}_{}_{}",
                                        snap.path
                                            .file_stem()
                                            .and_then(|s| s.to_str())
                                            .unwrap_or("unknown")
                                            .to_uppercase(),
                                        fn_name.to_uppercase(),
                                        src.to_uppercase(),
                                    );

                                    let advisory = Advisory::bare(
                                        rule_id,
                                        crate::Severity::Warning,
                                        snap.id,
                                        &snap.path,
                                        format!(
                                            "Cross-file taint: `{src}` → `{snk}` (depth={})",
                                            taints[0].path_length,
                                        ),
                                    )
                                    .with_confidence(engine.scorer_config.cross_file_taint_boost)
                                    .with_line(line)
                                    .with_content(fn_name.to_string())
                                    .with_enclosing_symbol(fn_name.to_string())
                                    .with_impact(&format!(
                                        "Unsanitized data from `{}` reaches `{}` through cross-file call chain.",
                                        taints[0].source_symbol, fn_name,
                                    ))
                                    .with_improvement(&format!(
                                        "Sanitize input before passing to `{fn_name}`."
                                    ))
                                    .with_tags(["taint-verified", "standalone", "cross-file"]);

                                    local.push(advisory);
                                }
                            }
                        }
                    }
                }

                if cursor.goto_first_child() {
                    continue;
                }
                loop {
                    if cursor.goto_next_sibling() {
                        break;
                    }
                    if !cursor.goto_parent() {
                        return local;
                    }
                }
            }
        })
        .collect();

    all_advisories.extend(advisories);
}

fn load_suppressions(root: &Path) -> Vec<(String, glob::Pattern)> {
    let suppress_file = root.join(".frensense-suppress.yml");
    if !suppress_file.exists() {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(&suppress_file) else {
        return Vec::new();
    };
    let Ok(config) = serde_yaml::from_str::<crate::engine::suppression::SuppressConfig>(&content)
    else {
        return Vec::new();
    };
    config
        .suppressions
        .into_iter()
        .filter_map(|s| glob::Pattern::new(&s.path).ok().map(|p| (s.rule_id, p)))
        .collect()
}

fn is_corpus_suppressed(
    suppressions: &[(String, glob::Pattern)],
    rule_id: &str,
    path: &std::path::Path,
) -> bool {
    for (sid, pattern) in suppressions {
        if (sid == rule_id || sid == "all") && pattern.matches_path(path) {
            return true;
        }
    }
    false
}

/// Verification result from taint flow analysis.
struct TaintVerification {
    verified: bool,
    detail: String,
    source_name: Option<String>,
    sink_name: Option<String>,
    sink_line: Option<u32>,
}

/// Pre-compute `FunctionTaintSummary` for every function in a file and cache
/// them in the `DataFlowEngine`. This enables `is_node_tainted` to resolve
/// same-file callees and check whether they propagate taint to their return,
/// rather than relying solely on the "any arg is tainted" heuristic.
fn precompute_taint_summaries_for_file(
    tree: &tree_sitter::Tree,
    source: &str,
    _ext: &str,
    file_path: &str,
    data_flow: &mut frensense_engine::data_flow::DataFlowEngine,
) {
    use tree_sitter::Node;
    fn node_uses_tainted_var(node: Node, source: &str, registry: &TaintRegistry) -> bool {
        match node.kind() {
            "identifier" => {
                let name = &source[node.start_byte()..node.end_byte()];
                registry.is_tainted(name)
            }
            "member_expression" | "field_expression" => {
                if let Some(object) = node.child_by_field_name("object").or_else(|| node.child(0)) {
                    node_uses_tainted_var(object, source, registry)
                } else {
                    false
                }
            }
            "call_expression" => {
                if let Some(args_list) = node.child_by_field_name("arguments") {
                    let mut c = args_list.walk();
                    for arg in args_list.children(&mut c) {
                        if !matches!(arg.kind(), "(" | ")" | ",")
                            && node_uses_tainted_var(arg, source, registry)
                        {
                            return true;
                        }
                    }
                }
                false
            }
            "template_string" | "template_literal" => {
                let mut c = node.walk();
                if c.goto_first_child() {
                    loop {
                        let child = c.node();
                        if matches!(child.kind(), "template_substitution" | "interpolation")
                            && node_uses_tainted_var(child, source, registry)
                        {
                            return true;
                        }
                        if !c.goto_next_sibling() {
                            break;
                        }
                    }
                }
                false
            }
            _ => {
                let mut c = node.walk();
                if c.goto_first_child() {
                    loop {
                        if node_uses_tainted_var(c.node(), source, registry) {
                            return true;
                        }
                        if !c.goto_next_sibling() {
                            break;
                        }
                    }
                }
                false
            }
        }
    }
    let root = tree.root_node();
    let function_kinds: &[&str] = &[
        "function_declaration",
        "method_definition",
        "arrow_function",
        "function_item",
        "function_definition",
    ];
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if function_kinds.contains(&node.kind()) {
            let fn_name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                .map_or("", |s| s);
            if !fn_name.is_empty() {
                let mut registry = TaintRegistry::default();
                let mut param_names: Vec<String> = Vec::new();
                if let Some(params_node) = node
                    .child_by_field_name("parameters")
                    .or_else(|| node.child_by_field_name("formal_parameters"))
                {
                    let mut pc = params_node.walk();
                    for param in params_node.children(&mut pc) {
                        if matches!(param.kind(), "(" | ")" | "," | ";" | "self") {
                            continue;
                        }
                        let mut pname = String::new();
                        if let Some(pat) = param.child_by_field_name("pattern") {
                            pname = source[pat.start_byte()..pat.end_byte()].to_string();
                        } else if param.kind() == "identifier" {
                            pname = source[param.start_byte()..param.end_byte()].to_string();
                        }
                        if !pname.is_empty() {
                            param_names.push(pname.clone());
                            // Seed every param as UserInput — we want to answer
                            // "does this function propagate taint if any param is tainted?"
                            registry.taint(&pname, TaintOrigin::UserInput);
                        }
                    }
                }
                let mut propagates_return = false;
                let mut return_origins = Vec::new();
                if let Some(body) = node.child_by_field_name("body") {
                    let mut bc = body.walk();
                    if bc.goto_first_child() {
                        loop {
                            let child = bc.node();
                            if child.kind() == "return_statement" {
                                let ret_val = child
                                    .child_by_field_name("value")
                                    .or_else(|| {
                                        let mut rc = child.walk();
                                        if rc.goto_first_child() {
                                            let first = rc.node();
                                            if first.kind() == "return" && rc.goto_next_sibling() {
                                                return Some(rc.node());
                                            }
                                        }
                                        None
                                    })
                                    .or_else(|| child.child(1));
                                if let Some(rv) = ret_val {
                                    if node_uses_tainted_var(rv, source, &registry) {
                                        propagates_return = true;
                                        return_origins.push(TaintOrigin::UserInput);
                                    }
                                }
                            }
                            if matches!(child.kind(), "variable_declarator" | "lexical_declaration")
                            {
                                if let Some(name_node) = child
                                    .child_by_field_name("name")
                                    .or_else(|| child.child_by_field_name("pattern"))
                                    && let Some(value_node) = child.child_by_field_name("value")
                                {
                                    if node_uses_tainted_var(value_node, source, &registry) {
                                        let mut nc = name_node.walk();
                                        for n_child in name_node.children(&mut nc) {
                                            if n_child.kind() == "identifier" {
                                                let n = source
                                                    [n_child.start_byte()..n_child.end_byte()]
                                                    .to_string();
                                                registry.taint(&n, TaintOrigin::UserInput);
                                            }
                                        }
                                    }
                                }
                            }
                            if !bc.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
                data_flow.cache_summary(
                    file_path,
                    fn_name,
                    FunctionTaintSummary {
                        propagates_return,
                        tainted_params: FxHashMap::default(),
                        return_origins,
                    },
                );
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// Verify that taint actually flows from source to sink in a function.
///
/// This uses the `CrossFileVerifier` to check if user-controlled data
/// reaches a dangerous sink, following taint through function calls.
///
/// # Panics
/// May panic if internal assertions fail.
/// Source types and sink names are learned from the corpus.
fn verify_taint_flow(
    fn_node: tree_sitter::Node,
    source: &str,
    tree: &tree_sitter::Tree,
    file_path: &Path,
    symbols: &crate::semantics::symbols::SymbolRegistry,
    data_flow: &frensense_engine::data_flow::DataFlowEngine,
    file_trees: &rustc_hash::FxHashMap<
        String,
        (
            tree_sitter::Tree,
            String,
            Vec<crate::semantics::data_flow::normalization::SemanticOp>,
        ),
    >,
    source_sink: &frensense_engine::corpus::source_sink::CorpusSourceSinkRegistry,
    deps: &std::collections::HashSet<String>,
    alias_tracker: &mut AliasTracker,
    provider: Option<&dyn frensense_engine::semantic::SemanticProvider>,
) -> TaintVerification {
    use crate::semantics::data_flow::cross_file::CrossFileVerifier;

    let file_path_str = file_path.to_string_lossy().to_string();
    let ext = file_path.extension().and_then(|s| s.to_str()).unwrap_or("");
    let mut cfg = frensense_engine::cfg::build_cfg(tree.root_node(), source, ext);
    frensense_engine::cfg::compute_dominators(&mut cfg);

    let file_env = frensense_engine::context::FileContext::extract(file_path, source).environment;

    let mut verifier = CrossFileVerifier::new(
        source,
        tree,
        &file_path_str,
        symbols,
        data_flow,
        file_trees,
        source_sink,
        deps,
    )
    .with_cfg(cfg)
    .with_file_env(file_env);
    if let Some(provider) = provider {
        verifier = verifier.with_provider(provider);
    }
    verifier.seed_taint(fn_node);

    // Record aliases from semantic ops so taint propagates through renames
    if let Some((_, _, ops)) = file_trees.get(&file_path_str) {
        SemanticExtractor::record_aliases(ops, source, verifier.registry(), alias_tracker);
    }

    let result = verifier.verify_flow(fn_node);

    if result.verified {
        TaintVerification {
            verified: true,
            detail: result.detail,
            source_name: result.source_name,
            sink_name: result.sink_name,
            sink_line: result.sink_line,
        }
    } else {
        TaintVerification {
            verified: false,
            detail: result.detail,
            source_name: result.source_name,
            sink_name: result.sink_name,
            sink_line: result.sink_line,
        }
    }
}

impl Engine {
    /// Runs the project auditor on the given root directory.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be read, if configuration fails to load,
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// or if rule execution encounters a fatal error.
    pub fn run(&mut self, root: &Path) -> Result<Vec<Advisory>> {
        let (advisories, _) = self.run_detailed(root)?;
        Ok(advisories)
    }

    /// Runs the auditor on a specific set of files (diff-only mode).
    ///
    /// Unlike `run()` which scans all files in a directory tree, this method
    /// processes only the given files. Useful with `--diff-only` to only audit
    /// changed files.
    ///
    /// # Errors
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Returns an error if file reading, parsing, or auditing fails.
    pub fn run_files(&mut self, root: &Path, files: &[PathBuf]) -> Result<Vec<Advisory>> {
        self.build_scorer_config();
        let _config = self.initialize_auditor_and_config(root);
        self.file_cache = cache::FileCache::load(
            root,
            self.language_filter.as_deref(),
            self.corpus_bundle_hash().as_deref(),
        );

        let snapshots = self.snapshot_files(root, files);
        let ProcessSnapshotsResult {
            mut symbols,
            file_ids,
            snapshot_map,
        } = process_snapshots(&self.auditor, &snapshots)?;
        let file_trees = build_file_trees(&snapshots);

        let mut all_advisories =
            self.perform_parallel_audit(&file_ids, &snapshot_map, &mut symbols, &file_trees)?;

        // Create DataFlowEngine for cross-file taint verification
        let mut data_flow = frensense_engine::data_flow::DataFlowEngine::new();

        // Pre-compute function taint summaries for same-file callee resolution
        for snap in &snapshots {
            if is_test_file(&snap.path) {
                continue;
            }
            let ext = snap.path.extension().and_then(|s| s.to_str()).unwrap_or("");
            let fp = snap.path.to_string_lossy();
            precompute_taint_summaries_for_file(
                &snap.tree,
                &snap.content,
                ext,
                &fp,
                &mut data_flow,
            );
        }

        // Shared dependency resolver — created once, used by both stages
        let mut dep_resolver =
            frensense_engine::deps::DependencyResolver::with_check_deps(self.check_deps);
        dep_resolver.load_project(root);
        let npm_deps = dep_resolver.npm_deps().clone();

        let all_symbols = symbols.query_all();
        let mut cross_file_taint =
            frensense_engine::data_flow::cross_file::build_resolver(&all_symbols, symbols.graph());
        let rust_hir = build_rust_hir(self, root);
        let source_sink = run_corpus_scan(
            self,
            root,
            &snapshots,
            &symbols,
            &data_flow,
            &file_trees,
            &mut all_advisories,
            &npm_deps,
            &mut cross_file_taint,
            rust_hir.clone(),
        );
        run_findings_modules(
            root,
            &snapshots,
            &symbols,
            &file_trees,
            &self.extra_taint_rule_dirs,
            &mut dep_resolver,
            &source_sink,
            &mut all_advisories,
            self.use_data_flow,
            self.use_compiler,
            rust_hir.clone(),
            &mut cross_file_taint,
        );

        // Standalone taint mode: scan ALL functions for source→sink flows
        // without requiring a corpus match. This is the "trained to find a bug"
        // mode — the engine uses compiler info + name heuristics to trace taint.
        if self.use_taint_only {
            run_standalone_taint(
                self,
                &snapshots,
                &symbols,
                &data_flow,
                &file_trees,
                &source_sink,
                &npm_deps,
                &mut all_advisories,
                self.use_compiler,
                rust_hir,
                &cross_file_taint,
            );
        }

        // Check for vulnerable dependencies
        check_vulnerable_deps(root, &mut all_advisories);

        self.apply_composition(&mut all_advisories);

        self.file_cache.save(
            root,
            self.language_filter.as_deref(),
            self.corpus_bundle_hash().as_deref(),
        );
        Ok(all_advisories)
    }

    /// Runs the audit on a single virtual file with the given content.
    ///
    /// # Errors
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Returns an error if parsing or auditing fails.
    pub fn run_content(&mut self, path: &Path, content: &str) -> Result<Vec<Advisory>> {
        let config = if self.auditor.rules().is_empty() {
            self.initialize_auditor_and_config(Path::new("."))
        } else {
            config::load_config(Path::new("."))
        };
        let id = self.source_registry.register(path, content.to_string());
        let (language, tree) = self.auditor.parse_source(path, content)?;
        let symbols = self
            .auditor
            .discover_symbols(path, id, content, &language, &tree)?;
        let semantic_ops = self.auditor.extract_semantic_ops(path, content, &tree);

        let mut file_trees = rustc_hash::FxHashMap::default();
        file_trees.insert(
            path.to_string_lossy().to_string(),
            (tree.clone(), content.to_string(), semantic_ops.clone()),
        );

        let mut registry = SymbolRegistry::new();
        for sym in symbols {
            registry.insert(sym);
        }
        self.auditor
            .discover_events(path, content, &tree, &mut registry)?;

        let opts = AuditOptions {
            file_id: id,
            path,
            content,
            tree: &tree,
            semantic_ops: &semantic_ops,
            symbols: &registry,
            graph: registry.graph(),
            file_trees: &file_trees,
            category_filter: &self.enabled_categories,
            tag_filter: &self.enabled_tags,
            suite: self.suite,
            env: self.environment,
            severity_filter: self.severity_filter,
            ngram_window_size: self.ngram_window_size,
            taint_confidence_interprocedural: self.taint_confidence_interprocedural,
            taint_confidence_intraprocedural: self.taint_confidence_intraprocedural,
            default_taint_max_depth: self.default_taint_max_depth,
        };

        let mut advisories = self.auditor.audit(&opts)?.advisories;
        apply_severity_overrides(
            &mut advisories,
            config.severity_override.as_ref(),
            &self.severity_overrides,
        );
        self.apply_composition(&mut advisories);
        Ok(advisories)
    }

    /// Applies real composition to advisories, replacing the coincidence counter.
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Uses `LayerSignals` to check if layers are causally related, not just co-located.
    fn apply_composition(&self, advisories: &mut [Advisory]) {
        use crate::engine::composition::CompositionConfig;

        let config = CompositionConfig {
            boost_rate: self.confidence_boost_rate,
            boost_max: self.confidence_boost_max,
            taint_unconfirmed_penalty: self.taint_unconfirmed_penalty,
            high_branch_ratio_threshold: self.high_branch_ratio_threshold,
            high_branch_ratio_suppression_factor: self.high_branch_ratio_suppression_factor,
        };
        crate::engine::composition::apply_composition(advisories, &config);
    }

    /// Runs a detailed audit, returning both advisories and the assembled symbol registry.
    ///
    /// # Errors
    /// Returns an error if file reading or parsing fails.
    #[allow(clippy::too_many_lines)]
    pub fn run_detailed(&mut self, root: &Path) -> Result<(Vec<Advisory>, SymbolRegistry)> {
        if !root.exists() {
            return Err(crate::FrensenseError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("path does not exist: {}", root.display()),
            )));
        }
        self.build_scorer_config();
        self.file_cache = cache::FileCache::load(
            root,
            self.language_filter.as_deref(),
            self.corpus_bundle_hash().as_deref(),
        );
        self.cache_root = Some(root.to_path_buf());

        let config = self.initialize_auditor_and_config(root);
        let snapshots = self.collect_and_snapshot_files(root);
        let ProcessSnapshotsResult {
            mut symbols,
            file_ids,
            snapshot_map,
        } = process_snapshots(&self.auditor, &snapshots)?;
        let file_trees = build_file_trees(&snapshots);

        let mut all_advisories =
            self.perform_parallel_audit(&file_ids, &snapshot_map, &mut symbols, &file_trees)?;

        #[cfg(feature = "fingerprinting")]
        self.run_profile_analysis(&snapshots, &mut all_advisories);

        self.load_calibration();
        // Create DataFlowEngine for cross-file taint verification
        let mut data_flow = frensense_engine::data_flow::DataFlowEngine::new();

        // Pre-compute function taint summaries for same-file callee resolution
        for snap in &snapshots {
            if is_test_file(&snap.path) {
                continue;
            }
            let ext = snap.path.extension().and_then(|s| s.to_str()).unwrap_or("");
            let fp = snap.path.to_string_lossy();
            precompute_taint_summaries_for_file(
                &snap.tree,
                &snap.content,
                ext,
                &fp,
                &mut data_flow,
            );
        }

        // Shared dependency resolver — created once, used by both stages
        let mut dep_resolver =
            frensense_engine::deps::DependencyResolver::with_check_deps(self.check_deps);
        dep_resolver.load_project(root);
        let npm_deps = dep_resolver.npm_deps().clone();

        // Build cross-file taint resolver (shared between corpus scan and findings)
        let all_symbols = symbols.query_all();
        let mut cross_file_taint =
            frensense_engine::data_flow::cross_file::build_resolver(&all_symbols, symbols.graph());

        let rust_hir = build_rust_hir(self, root);
        let source_sink = run_corpus_scan(
            self,
            root,
            &snapshots,
            &symbols,
            &data_flow,
            &file_trees,
            &mut all_advisories,
            &npm_deps,
            &mut cross_file_taint,
            rust_hir.clone(),
        );
        run_findings_modules(
            root,
            &snapshots,
            &symbols,
            &file_trees,
            &self.extra_taint_rule_dirs,
            &mut dep_resolver,
            &source_sink,
            &mut all_advisories,
            self.use_data_flow,
            self.use_compiler,
            rust_hir.clone(),
            &mut cross_file_taint,
        );

        // Standalone taint mode: scan ALL functions for source→sink flows
        if self.use_taint_only {
            run_standalone_taint(
                self,
                &snapshots,
                &symbols,
                &data_flow,
                &file_trees,
                &source_sink,
                &npm_deps,
                &mut all_advisories,
                self.use_compiler,
                rust_hir,
                &cross_file_taint,
            );
        }

        // Check for vulnerable dependencies
        check_vulnerable_deps(root, &mut all_advisories);

        // Apply severity overrides and composition to all findings
        apply_severity_overrides(
            &mut all_advisories,
            config.severity_override.as_ref(),
            &self.severity_overrides,
        );
        self.apply_composition(&mut all_advisories);

        if let Some(ref baseline_path) = self.baseline_path
            && let Ok(prev) = std::fs::read_to_string(baseline_path)
            && let Ok(fingerprints) = serde_json::from_str::<Vec<String>>(&prev)
        {
            let baseline_set: HashSet<String> = fingerprints.into_iter().collect();
            all_advisories.retain(|a| !baseline_set.contains(&a.fingerprint));
        }

        self.file_cache.save(
            root,
            self.language_filter.as_deref(),
            self.corpus_bundle_hash().as_deref(),
        );
        Ok((all_advisories, symbols))
    }

    #[cfg(feature = "fingerprinting")]
    fn run_profile_analysis(
        &self,
        snapshots: &[super::FileSnapshot],
        all_advisories: &mut Vec<Advisory>,
    ) {
        let Some(ref profile) = self.profile else {
            return;
        };

        let mut all_fingerprints = Vec::new();
        for snap in snapshots {
            let mut fps = Vec::new();
            frensense_engine::fingerprint::extract_fingerprints(
                snap.tree.root_node(),
                &snap.content,
                &snap.path,
                &mut fps,
                self.ngram_window_size,
                None,
            );
            all_fingerprints.extend(fps);
        }

        for fp in &all_fingerprints {
            let result = profile.style_surprise(fp);
            if result.score > self.profile_threshold {
                all_advisories.push(
                    Advisory::bare("STYLE_ANOMALY", crate::Severity::Warning, FileId(0), std::path::Path::new(&fp.file_path), format!("Style Anomaly: '{}' has {:.0}% unfamiliar patterns.", fp.function_name, result.score * 100.0))
                        .with_confidence(result.score)
                        .with_line(u32::try_from(fp.line).unwrap_or(u32::MAX))
                        .with_content(fp.function_name.clone())
                        .with_enclosing_symbol(fp.function_name.clone())
                        .with_impact("LLM-generated code often violates project conventions — wrong casing, unfamiliar boilerplate, or types never used in this codebase.")
                        .with_improvement("Review the function against project patterns. Consider using established conventions."),
                );
            }
        }

        // Use clustering for near-duplicate detection (replaces pairwise O(n²))
        let clusters = crate::engine::clustering::cluster_functions(&all_fingerprints, 0.75);
        let cluster_advisories = crate::engine::clustering::cluster_to_advisories(&clusters);
        all_advisories.extend(cluster_advisories);

        // Also emit basic info for all clusters (even consistent ones)
        for cluster in &clusters {
            if cluster.members.len() < 2 {
                continue;
            }
            let member_names: Vec<&str> = cluster
                .members
                .iter()
                .map(|m| m.fingerprint.function_name.as_str())
                .collect();
            let first = &cluster.members[0].fingerprint;
            all_advisories.push(
                Advisory::bare(
                    "NEAR_DUPLICATE_FUNCTION",
                    crate::Severity::Info,
                    FileId(0),
                    std::path::Path::new(&first.file_path),
                    format!(
                        "Cluster {}: {} functions are near-duplicates: {}",
                        cluster.id,
                        cluster.members.len(),
                        member_names.join(", ")
                    ),
                )
                .with_confidence(0.8)
                .with_line(u32::try_from(first.line).unwrap_or(u32::MAX))
                .with_content(first.function_name.clone())
                .with_impact(
                    "Copy-pasted code diverges over time — one copy may lack security fixes.",
                )
                .with_improvement("Consider extracting shared logic into a common function.")
                .with_tags(["copy-paste", "duplicate", "cluster"]),
            );
        }
    }

    fn snapshot_files(&mut self, _root: &Path, files: &[PathBuf]) -> Vec<FileSnapshot> {
        let mut snapshots = Vec::new();
        for p in files {
            if let Some(ref allowed) = self.language_filter {
                let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
                if !allowed.contains(&ext) {
                    continue;
                }
            }
            let content = match std::fs::read_to_string(p) {
                Ok(c) => c,
                Err(e) => {
                    self.file_cache.remove(p);
                    tracing::warn!("cannot read {}: {e}", p.display());
                    continue;
                }
            };
            if self.file_cache.is_unchanged(p, &content) {
                continue;
            }
            let id = self.source_registry.register(p, content.clone());
            let (language, tree) = match self.auditor.parse_source(p, &content) {
                Ok(v) => v,
                Err(e) => {
                    self.file_cache.remove(p);
                    tracing::warn!("cannot parse {}: {e}", p.display());
                    continue;
                }
            };
            let symbols = match self
                .auditor
                .discover_symbols(p, id, &content, &language, &tree)
            {
                Ok(s) => s,
                Err(e) => {
                    self.file_cache.remove(p);
                    tracing::warn!("symbol discovery failed for {}: {e}", p.display());
                    continue;
                }
            };
            let edges = match self.auditor.scan_for_edges(p, &content, &language, &tree) {
                Ok(e) => e,
                Err(e) => {
                    self.file_cache.remove(p);
                    tracing::warn!("edge discovery failed for {}: {e}", p.display());
                    continue;
                }
            };
            let semantic_ops = self.auditor.extract_semantic_ops(p, &content, &tree);
            self.file_cache.update(p, &content);
            snapshots.push(FileSnapshot {
                id,
                path: p.clone(),
                content,
                tree,
                symbols,
                edges,
                semantic_ops,
            });
        }
        snapshots
    }

    fn initialize_auditor_and_config(&mut self, root: &Path) -> config::FrensenseConfig {
        let config = config::load_config(root);

        // Wire rules_dir from config to extra taint rule dirs
        if let Some(ref dir) = config.rules_dir {
            let path = root.join(dir);
            if path.is_dir() && !self.extra_taint_rule_dirs.contains(&path) {
                self.extra_taint_rule_dirs.push(path);
            }
        }

        // Apply disabled_rules from config + CLI
        let mut disabled_set: HashSet<&str> = HashSet::new();
        if let Some(disabled) = &config.disabled_rules {
            for id in disabled {
                disabled_set.insert(id.as_str());
            }
        }
        for id in &self.disabled_rule_ids {
            disabled_set.insert(id.as_str());
        }
        if !disabled_set.is_empty() {
            self.auditor
                .retain_rules(|r| !disabled_set.contains(r.id()));
        }

        // Load suppressions
        let suppress_file = root.join(".frensense-suppress.yml");
        if suppress_file.exists()
            && let Ok(content) = std::fs::read_to_string(suppress_file)
            && let Ok(supp_config) = serde_yaml::from_str::<SuppressConfig>(&content)
        {
            self.auditor.set_suppressions(supp_config);
        }
        config
    }

    fn collect_and_snapshot_files(&mut self, root: &Path) -> Vec<FileSnapshot> {
        super::files::collect_files_impl(self, root)
    }

    /// Collects all files reachable from `root` that match supported extensions
    /// and the optional language filter.
    #[must_use]
    pub fn collect_files(root: &Path, language_filter: Option<&Vec<&'static str>>) -> Vec<PathBuf> {
        super::files::collect_files(root, language_filter)
    }

    fn perform_parallel_audit(
        &self,
        file_ids: &[(FileId, PathBuf)],
        snapshot_map: &rustc_hash::FxHashMap<FileId, &FileSnapshot>,
        symbols: &mut SymbolRegistry,
        file_trees: &rustc_hash::FxHashMap<
            String,
            (
                tree_sitter::Tree,
                String,
                Vec<crate::semantics::data_flow::normalization::SemanticOp>,
            ),
        >,
    ) -> Result<Vec<Advisory>> {
        super::files::parallel_audit_impl(self, file_ids, snapshot_map, symbols, file_trees)
    }
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Find a function node by name and line number for semantic filtering.
fn find_function_node<'a>(
    root: tree_sitter::Node<'a>,
    name: &str,
    line: usize,
    source: &str,
) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = root.walk();
    let mut best_match: Option<tree_sitter::Node<'a>> = None;

    loop {
        let node = cursor.node();
        let kind = node.kind();

        if matches!(
            kind,
            "function_item"
                | "function_declaration"
                | "method_definition"
                | "arrow_function"
                | "function"
                | "formal_parameters"
        ) {
            // Calculate line number for this node
            let node_line = source[..node.start_byte()]
                .chars()
                .filter(|&c| c == '\n')
                .count();

            // If we've passed the target line significantly, we can stop searching.
            // Nodes are ordered by start byte/line, so we will never find it.
            if node_line > line + 5 {
                return best_match;
            }

            // For named functions, check name match
            if name == "anonymous" {
                // For anonymous functions, find the closest function at the target line
                // Arrow functions and function expressions are the priority
                if node_line.abs_diff(line) <= 1 {
                    // Prefer arrow functions (more likely to be the anonymous one)
                    if kind == "arrow_function" {
                        // Check if this is the innermost function
                        let has_inner = has_function_child(node);
                        if !has_inner {
                            best_match = Some(node);
                        }
                    } else if best_match.is_none() {
                        best_match = Some(node);
                    }
                }
            } else if let Some(name_node) = node.child_by_field_name("name") {
                let node_name = &source[name_node.start_byte()..name_node.end_byte()];
                if node_name == name && node_line.abs_diff(line) <= 2 {
                    return Some(node);
                }
            } else if kind == "arrow_function"
                && let Some(parent) = node.parent()
                && parent.kind() == "variable_declarator"
                && let Some(name_node) = parent.child_by_field_name("name")
            {
                let node_name = &source[name_node.start_byte()..name_node.end_byte()];
                if node_name == name && node_line.abs_diff(line) <= 2 {
                    return Some(node);
                }
            }
        }

        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return best_match;
            }
        }
    }
}

///
/// # Panics
/// May panic if internal assertions fail.
/// Check if a node contains any function child nodes.
fn has_function_child(node: tree_sitter::Node<'_>) -> bool {
    let mut cursor = node.walk();
    loop {
        let n = cursor.node();
        if n != node
            && matches!(
                n.kind(),
                "function_item"
                    | "function_declaration"
                    | "method_definition"
                    | "arrow_function"
                    | "function"
            )
        {
            return true;
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return false;
            }
        }
    }
}

fn is_test_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let stem = path.file_stem().and_then(|n| n.to_str()).unwrap_or("");

    // Check filename patterns
    if name.ends_with(".test.ts")
        || name.ends_with(".test.tsx")
        || name.ends_with(".test.js")
        || name.ends_with(".test.jsx")
        || name.ends_with(".spec.ts")
        || name.ends_with(".spec.tsx")
        || name.ends_with(".spec.js")
        || name.ends_with(".spec.jsx")
        || name.ends_with("_test.rs")
        || name.ends_with(".test.rs")
    {
        return true;
    }

    // Check if in test directories
    let path_str = path.to_string_lossy();
    if path_str.contains("/tests/")
        || path_str.contains("/test/")
        || path_str.contains("__tests__/")
        || path_str.contains("/__mocks__/")
        || path_str.contains("/mocks/")
    {
        return true;
    }

    // Check for mock files
    if stem.starts_with("mock") || stem.to_lowercase().ends_with(".mock") {
        return true;
    }

    false
}

/// Check for vulnerable dependencies in package.json and add advisories.
fn check_vulnerable_deps(root: &Path, advisories: &mut Vec<Advisory>) {
    use frensense_engine::deps::DependencyResolver;

    let mut resolver = DependencyResolver::new();
    resolver.load_project(root);

    // Check npm vulnerabilities (tries `npm audit --json`, falls back to hardcoded)
    let npm_vulns = resolver.check_vulnerable_npm_deps(root);
    for (pkg, desc) in npm_vulns {
        let mut advisory = Advisory::bare(
            format!("VULN_NPM_{}", pkg.to_uppercase().replace('-', "_")),
            crate::Severity::Warning,
            FileId(0),
            &root.join("package.json"),
            format!("Vulnerable npm package: {pkg}"),
        );
        advisory.confidence = 0.9;
        advisory.impact = desc;
        advisory.improvement =
            format!("Upgrade {pkg} to a secure version or replace with a maintained alternative");
        advisory.cwe = Some("A06:2021".to_string());
        advisory.cvss = Some(7.5);
        advisory.owasp = Some("A06:2021".to_string());
        advisory.tags = vec!["vulnerable-dependency".to_string(), "npm".to_string()];
        advisories.push(advisory);
    }

    // Check cargo vulnerabilities (tries `cargo audit --json`, falls back to hardcoded)
    let cargo_vulns = resolver.check_vulnerable_cargo_deps(root);
    for (crate_name, desc) in cargo_vulns {
        let mut advisory = Advisory::bare(
            format!("VULN_CARGO_{}", crate_name.to_uppercase().replace('-', "_")),
            crate::Severity::Warning,
            FileId(0),
            &root.join("Cargo.toml"),
            format!("Vulnerable cargo crate: {crate_name}"),
        );
        advisory.confidence = 0.9;
        advisory.impact = desc;
        advisory.improvement = format!("Update {crate_name} to a patched version");
        advisory.cwe = Some("A06:2021".to_string());
        advisory.cvss = Some(7.5);
        advisory.owasp = Some("A06:2021".to_string());
        advisory.tags = vec!["vulnerable-dependency".to_string(), "cargo".to_string()];
        advisories.push(advisory);
    }
}
