// SPDX-License-Identifier: MIT

use super::{Engine, FileSnapshot};
use crate::engine::auditor::{AuditOptions, ScanResult};
use crate::parser::ParserRegistry;
use crate::semantics::symbols::SymbolRegistry;
use crate::{Advisory, FileId, Result};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Collects all files reachable from `root` that match supported extensions
///
/// # Panics
/// May panic if internal assertions fail.
/// and the optional language filter.
pub fn collect_files(root: &Path, language_filter: Option<&Vec<&'static str>>) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            if e.file_type().is_dir() {
                if e.path() != root {
                    return name != "target"
                        && name != "node_modules"
                        && name != "dist"
                        && name != "build"
                        && name != "vendor"
                        && name != "out"
                        && name != ".next"
                        && name != ".nuxt"
                        && name != ".cache"
                        && name != "coverage"
                        && name != "cypress"
                        && name != "playwright"
                        && name != "storybook-static"
                        && name != "frontend"
                        && !name.starts_with('.');
                }
            } else if e.file_type().is_file() {
                // Skip files larger than 500KB (likely bundled or generated)
                if let Ok(meta) = e.metadata()
                    && meta.len() > 500_000
                {
                    return false;
                }
                if name.ends_with(".min.js")
                    || name.ends_with(".bundle.js")
                    || name.ends_with(".chunk.js")
                    || name.ends_with(".debug.js")
                {
                    return false;
                }
            }
            true
        })
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .filter(|p| ParserRegistry::is_supported(p))
        .filter(|p| !is_test_file(p))
        .filter(|p| {
            if let Some(allowed) = language_filter {
                let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
                allowed.contains(&ext)
            } else {
                true
            }
        })
        .collect()
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
        || name == "mod.rs" && path.to_string_lossy().contains("/tests/")
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

pub(crate) fn collect_files_impl(engine: &mut Engine, root: &Path) -> Vec<FileSnapshot> {
    use rayon::prelude::*;
    let files = collect_files(root, engine.language_filter.as_ref());

    // Pre-assign file IDs from a monotonic counter before any parallel work.
    // Phase 1 + 2 merged: read, parse, and discover symbols in parallel.
    // Extract what we need before the parallel section (no &mut access in par_iter).
    let file_cache: &crate::engine::project::cache::FileCache = &engine.file_cache;
    let auditor: &crate::engine::auditor::FrensenseAuditor = &engine.auditor;
    let parsed_results: Vec<_> = files
        .into_par_iter()
        .enumerate()
        .map(|(seq, p)| {
            let id = FileId(seq as u32);
            let content = match std::fs::read_to_string(&p) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("skipping unreadable file {}: {e}", p.display());
                    return Err((p, false));
                }
            };

            let unchanged = file_cache.is_unchanged(&p, &content);
            if unchanged {
                if let Ok((_language, tree)) = auditor.parse_source(&p, &content) {
                    return Ok((
                        id,
                        p,
                        content,
                        tree,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        true,
                    ));
                }
                return Err((p, false));
            }

            match auditor.parse_source(&p, &content) {
                Ok((language, tree)) => {
                    let symbols = auditor.discover_symbols(&p, id, &content, &language, &tree);
                    let edges = auditor.scan_for_edges(&p, &content, &language, &tree);
                    let semantic_ops = auditor.extract_semantic_ops(&p, &content, &tree);

                    if let (Ok(symbols), Ok(edges)) = (symbols, edges) {
                        Ok((id, p, content, tree, symbols, edges, semantic_ops, false))
                    } else {
                        tracing::warn!("symbol or edge discovery failed for {}", p.display());
                        Err((p, false))
                    }
                }
                Err(e) => {
                    tracing::warn!("skipping unparseable file {}: {e}", p.display());
                    Err((p, false))
                }
            }
        })
        .collect();

    // Phase 3: Register sources and build snapshots sequentially.
    let mut snapshots = Vec::new();
    for res in parsed_results {
        match res {
            Ok((_pre_id, p, content, tree, symbols, edges, semantic_ops, was_unchanged)) => {
                let id = engine.source_registry.register(&p, content.clone());
                if !was_unchanged {
                    engine.file_cache.update(&p, &content);
                }
                snapshots.push(FileSnapshot {
                    id,
                    path: p,
                    content,
                    tree,
                    symbols,
                    edges,
                    semantic_ops,
                });
            }
            Err((p, _was_unchanged)) => {
                engine.file_cache.remove(&p);
            }
        }
    }

    tracing::info!(count = snapshots.len(), "finished collect_files_impl");
    snapshots
}

pub(crate) fn parallel_audit_impl(
    engine: &Engine,
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
    use rayon::prelude::*;

    let results: Result<Vec<ScanResult>> = file_ids
        .par_iter()
        .map(|(id, p)| {
            let snap = snapshot_map.get(id).ok_or_else(|| {
                crate::FrensenseError::Engine(format!(
                    "Missing snapshot for file ID {} at path {}",
                    id.0,
                    p.display()
                ))
            })?;
            let opts = AuditOptions {
                file_id: *id,
                path: p,
                content: &snap.content,
                tree: &snap.tree,
                semantic_ops: &snap.semantic_ops,
                symbols,
                graph: symbols.graph(),
                file_trees,
                category_filter: &engine.enabled_categories,
                tag_filter: &engine.enabled_tags,
                suite: engine.suite,
                env: engine.environment,
                severity_filter: engine.severity_filter,
                ngram_window_size: engine.ngram_window_size,
                taint_confidence_interprocedural: engine.taint_confidence_interprocedural,
                taint_confidence_intraprocedural: engine.taint_confidence_intraprocedural,
                default_taint_max_depth: engine.default_taint_max_depth,
            };
            engine.auditor.audit(&opts)
        })
        .collect();

    let mut all_advisories = Vec::new();
    for result in results? {
        for adv in &result.advisories {
            if let Some(ref sym) = adv.enclosing_symbol {
                let graph = symbols.graph_mut();
                graph.record_taint_flow(crate::semantics::graph::TaintFlowRecord {
                    function_name: sym.clone(),
                    file_path: adv.file_path.clone(),
                    source_pattern: String::new(),
                    sink_pattern: String::new(),
                    rule_id: adv.rule_id.clone(),
                });
            }
        }
        for a in result.advisories {
            if a.confidence >= engine.min_confidence {
                all_advisories.push(a);
            }
        }
    }
    Ok(all_advisories)
}
