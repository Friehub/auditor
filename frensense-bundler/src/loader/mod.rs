pub mod features;
pub mod fs;
pub mod metadata;
pub mod types;

use features::{collect_all_function_features, learn_from_features, FunctionFeatures};
use fs::{collect_corpus_files, extract_pattern_name, is_negative_file};
use metadata::{load_sidecar_toml, parse_frensense_block, synthesize_advisory};
use types::AdvisoryText;
pub use types::{CorpusPattern, LoadWarning};

// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::path::Path;

use frensense_engine::corpus::semantic::SemanticFilter;
use frensense_engine::fingerprint::{extract_fingerprints, FunctionFingerprint};
use frensense_lang::spec_for_ext;

pub fn load_corpus(corpus_dir: &Path) -> Result<(Vec<CorpusPattern>, Vec<LoadWarning>), String> {
    type PatternEntry = (
        Vec<FunctionFingerprint>,
        Vec<FunctionFingerprint>,
        AdvisoryText,
        Vec<FunctionFeatures>, // positive features
        Vec<FunctionFeatures>, // negative features
    );
    let mut pairs: HashMap<String, PatternEntry> = HashMap::new();

    if !corpus_dir.exists() {
        return Err(format!(
            "corpus directory does not exist: {}",
            corpus_dir.display()
        ));
    }
    let entries = collect_corpus_files(corpus_dir);
    let mut warnings: Vec<LoadWarning> = Vec::new();
    for path in entries {
        println!("Processing {:?}", path);
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        let is_positive = file_name.contains("_positive");
        // M1: Support _negative, _negative2, _negative3 ... for diverse negatives
        let is_negative = is_negative_file(file_name);

        if !is_positive && !is_negative {
            continue;
        }

        let source = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let lang_name = frensense_engine::parser::ext_to_language(ext);
        if lang_name == "unknown" {
            // Unsupported extension: not a coverage gap (just an unrelated file type),
            // so skip silently rather than emitting a spurious warning.
            continue;
        }

        let mut parser = tree_sitter::Parser::new();
        let lang = frensense_engine::parser::ParserRegistry::get_language_by_name(lang_name)
            .map_err(|e| e.to_string())?;
        parser.set_language(&lang).map_err(|e| e.to_string())?;
        let Some(tree) = parser.parse(&source, None) else {
            continue;
        };

        let mut fps = Vec::new();
        extract_fingerprints(tree.root_node(), &source, &path, &mut fps, 5, None);

        if fps.is_empty() {
            continue;
        }

        // Collect features from all function nodes for semantic learning
        let mut all_features = Vec::new();
        let spec = spec_for_ext(ext);
        collect_all_function_features(tree.root_node(), &source, &mut all_features, spec);

        let pattern_name = extract_pattern_name(file_name);
        let entry = pairs.entry(pattern_name).or_default();
        if is_positive {
            entry.0.extend(fps);
            entry.3.extend(all_features);
            // Extract [frensense] block from positive file — primary source of advisory text
            if entry.2.observation.is_none() {
                entry.2 = parse_frensense_block(&source);
            }
            // M4: Auto-infer expected_context from the positive file path+content — no TOML needed
            if entry.2.expected_context.is_none() {
                entry.2.expected_context = Some(frensense_engine::context::FileContext::extract(
                    &path, &source,
                ));
            }
        } else {
            entry.1.extend(fps);
            entry.4.extend(all_features);
        }
    }

    let mut patterns = Vec::new();
    let semantic_filters = load_semantic_filters();
    for (name, (pos, neg, comment_advisory, pos_features, neg_features)) in pairs {
        if pos.is_empty() && neg.is_empty() {
            continue;
        }
        if pos.is_empty() {
            warnings.push(LoadWarning {
                pattern_id: name.clone(),
                message:
                    "has negative examples but no positive example — pattern skipped, coverage gap"
                        .to_string(),
            });
            continue;
        }
        if neg.is_empty() {
            warnings.push(LoadWarning {
                pattern_id: name.clone(),
                message: "has positive example but no negative example — pattern skipped, cannot learn boundary".to_string(),
            });
            continue;
        }

        // Priority: comment block > sidecar TOML (optional override) > synthesized
        // The sidecar TOML is NEVER required — it is only an escape hatch for edge cases.
        let toml_advisory = load_sidecar_toml(corpus_dir, &name);

        // Learn semantic constraints from positive/negative examples
        let learned = if !pos_features.is_empty() && !neg_features.is_empty() {
            // M2: Pass taint source awareness into constraint learning
            learn_from_features(&pos_features, &neg_features)
        } else {
            frensense_engine::corpus::semantic::LearnedConstraints::default()
        };

        // M3: Synthesize advisory text from learned constraints when no comment block is present
        let synthesized =
            synthesize_advisory(&name, &learned.required_calls, &learned.forbidden_calls);

        let observation = comment_advisory
            .observation
            .or(toml_advisory.observation)
            .or(synthesized.observation);
        let impact = comment_advisory
            .impact
            .or(toml_advisory.impact)
            .or(synthesized.impact);
        let improvement = comment_advisory
            .improvement
            .or(toml_advisory.improvement)
            .or(synthesized.improvement);

        // M4: Auto-context is already in comment_advisory.expected_context (set during file scan).
        // Sidecar TOML is a manual override; auto-inferred value is the fallback.
        let expected_context = toml_advisory
            .expected_context
            .or(comment_advisory.expected_context);

        // Merge: TOML manual filter takes precedence over learned constraints
        let filter = if let Some(manual) = semantic_filters.get(&name) {
            Some(manual.clone())
        } else if !learned.is_empty() {
            Some(learned.to_filter())
        } else {
            None
        };

        patterns.push(CorpusPattern {
            id: name.clone(),
            positives: pos,
            negatives: neg,
            semantic_filter: filter,
            observation,
            impact,
            improvement,
            expected_context,
            cwe: comment_advisory.cwe.or(toml_advisory.cwe),
            cvss: comment_advisory.cvss.or(toml_advisory.cvss),
            owasp: comment_advisory.owasp.or(toml_advisory.owasp),
            severity: comment_advisory.severity.or(toml_advisory.severity),
            runtime_probe: comment_advisory
                .runtime_probe
                .or(toml_advisory.runtime_probe),
        });
    }

    Ok((patterns, warnings))
}

/// Convenience wrapper: load corpus patterns, discarding non-fatal warnings.
/// Use `load_corpus` directly when you need to surface diagnostics to the user.
pub fn load_corpus_patterns(corpus_dir: &Path) -> Result<Vec<CorpusPattern>, String> {
    load_corpus(corpus_dir).map(|(patterns, _warnings)| patterns)
}

/// Load semantic filters from the TOML file.
pub fn load_semantic_filters() -> std::collections::HashMap<String, SemanticFilter> {
    // All semantic filters are now auto-learned from the corpus by
    // `compute_auto_filters` and stored in the FRC bundle.
    //
    // Hand-crafted filters were removed in commit 74a3a55.
    // If a pattern needs a constraint that the auto-learner doesn't
    // yet infer, add corpus positive/negative examples instead.
    //
    // The auto-learner currently infers:
    //   - contains_call_to (calls present in most positives)
    //   - contains_import (imports exclusive to a category)
    //   - excludes_call (calls in negatives but not positives) [disabled]
    //   - function_name_regex (common prefixes) [disabled]
    std::collections::HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_verify_sqli_api_calls_in_pattern() {
        use std::hash::{Hash, Hasher};
        let sqli_hash = {
            let mut h = rustc_hash::FxHasher::default();
            "models.sequelize.query".hash(&mut h);
            h.finish()
        };
        let dir = std::path::Path::new(
            "/home/oxisrael/Friehub/Taas/Frensene_main/Frensense/corpus/targets",
        );
        // Load patterns and check the sqli ones
        let (patterns, _warnings) = load_corpus(dir).unwrap();
        let sqli_patterns: Vec<_> = patterns
            .iter()
            .filter(|p| p.id.contains("sqli") && p.id.contains("models"))
            .collect();
        eprintln!("Found {} sqli+models patterns", sqli_patterns.len());
        for pat in &sqli_patterns {
            eprintln!(
                "  Pattern: {} ({} positives, {} negatives)",
                pat.id,
                pat.positives.len(),
                pat.negatives.len()
            );
            for (i, fp) in pat.positives.iter().enumerate() {
                let has = fp.api_calls.contains(&sqli_hash);
                eprintln!(
                    "    Positive[{}]: fn='{}' line={} has_sqli={} api_calls={} struct_markers={}",
                    i,
                    fp.function_name,
                    fp.line,
                    has,
                    fp.api_calls.len(),
                    fp.structural_markers.len()
                );
                if !has && fp.api_calls.len() <= 10 {
                    eprintln!("      api_calls={:?}", fp.api_calls);
                }
            }
        }

        // Now check if the sqli pattern matches login.ts by loading login.ts fingerprints
        let js_path =
            std::path::Path::new("/home/oxisrael/Friehub/Taas/juice-shop/routes/login.ts");
        let js_src = std::std::fs::read_to_string(js_path).unwrap();
        let mut parser = tree_sitter::Parser::new();
        let lang =
            frensense_engine::parser::ParserRegistry::get_language_by_name("typescript").unwrap();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(&js_src, None).unwrap();
        let mut js_fps = Vec::new();
        frensense_engine::fingerprint::extract_fingerprints(
            tree.root_node(),
            &js_src,
            js_path,
            &mut js_fps,
            5,
            None,
        );
        eprintln!("\nJuice Shop login.ts: {} fingerprints", js_fps.len());
        let has_sqli = js_fps.iter().any(|fp| fp.api_calls.contains(&sqli_hash));
        eprintln!("Juice Shop has models.sequelize.query: {}", has_sqli);
        for (i, fp) in js_fps.iter().enumerate() {
            let has = fp.api_calls.contains(&sqli_hash);
            eprintln!(
                "  [{}] fn='{}' line={} has_sqli={} api_calls={}",
                i,
                fp.function_name,
                fp.line,
                has,
                fp.api_calls.len()
            );
        }
        assert!(
            !sqli_patterns.is_empty(),
            "SQLi models patterns should exist"
        );
        assert!(
            has_sqli,
            "Juice Shop login.ts should have models.sequelize.query API call"
        );
    }

    #[test]
    fn debug_why_sqli_not_matching_registry() {
        use crate::pattern::scorer::PatternScorer;
        use frensense_engine::corpus::registry::PatternRegistry;
        use std::hash::{Hash, Hasher};

        // Load the corpus into registry
        let dir = std::path::Path::new(
            "/home/oxisrael/Friehub/Taas/Frensene_main/Frensense/corpus/targets",
        );
        let mut registry = PatternRegistry::new(0.0, 0.4, 0.20);
        registry.load_corpus(dir).unwrap();

        // Load JS login.ts
        let js_path =
            std::path::Path::new("/home/oxisrael/Friehub/Taas/juice-shop/routes/login.ts");
        let js_src = std::std::fs::read_to_string(js_path).unwrap();
        let mut parser = tree_sitter::Parser::new();
        let lang =
            frensense_engine::parser::ParserRegistry::get_language_by_name("typescript").unwrap();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(&js_src, None).unwrap();
        let mut js_fps = Vec::new();
        frensense_engine::fingerprint::extract_fingerprints(
            tree.root_node(),
            &js_src,
            js_path,
            &mut js_fps,
            5,
            None,
        );

        // Find the handler at line 32 (the vulnerable one)
        let handler = js_fps.iter().find(|fp| fp.line == 32).unwrap();

        // Scan the handler through the registry (no AST node, no source, no context)
        let scan_ctx = frensense_engine::corpus::registry::ScanContext::default();
        let matches = registry.scan_function(handler, &scan_ctx);

        // Find the SQLi match and print its evidence
        // Print evidence for the FIRST SQLi match with models
        let sqli_match = matches
            .iter()
            .find(|m| m.pattern_id.contains("sqli") && m.pattern_id.contains("models"));
        if let Some(m) = sqli_match {
            eprintln!(
                "\n--- Match evidence: id={} score={:.4} pos_sim={:.4} neg_sim={:.4} ---",
                m.pattern_id, m.score, m.positive_similarity, m.negative_similarity
            );
            if let Some(ref ev) = m.matched_evidence {
                eprintln!(
                    "  ngram_sim={:.4} ast_sim={:.4} sig_sim={:.4}",
                    ev.ngram_sim, ev.ast_sim, ev.signature_sim
                );
                eprintln!(
                    "  cf_sim={:.4} api_sim={:.4} motif_sim={:.4}",
                    ev.control_flow_sim, ev.api_sim, ev.motif_sim
                );
                eprintln!(
                    "  semantic_sim={:.4} flow_sim={:?} has_taint={}",
                    ev.semantic_sim, ev.flow_sim, ev.has_taint_path
                );
            }
        } else {
            eprintln!("\n--- No SQLi+models match found. First 3 matches: ---");
            for m in matches.iter().take(5) {
                eprintln!("  id={} score={:.4}", m.pattern_id, m.score);
            }
        }

        eprintln!("\nscan_function returned {} matches total", matches.len());
        for m in &matches {
            if m.pattern_id.contains("sqli") {
                eprintln!("  SQLi match: id={} score={:.4}", m.pattern_id, m.score);
            }
        }
        let sql_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.pattern_id.contains("sqli"))
            .collect();
        assert!(
            !sql_matches.is_empty(),
            "At least one sqli pattern should match login.ts handler"
        );
        let best_sqli = sql_matches
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap();
        eprintln!(
            "Best SQLi match: id={} score={:.4}",
            best_sqli.pattern_id, best_sqli.score
        );
        // Print ALL sqli match scores
        for m in sql_matches.iter().filter(|m| m.score >= 0.05) {
            eprintln!("  {} score={:.4}", m.pattern_id, m.score);
        }
    }

    #[test]
    fn test_extract_pattern_name() {
        assert_eq!(
            extract_pattern_name("rust_clone_in_loop_positive.rs"),
            "rust_clone_in_loop"
        );
        assert_eq!(
            extract_pattern_name("ts_command_injection_negative.ts"),
            "ts_command_injection"
        );
    }

    #[test]
    fn test_empty_directory_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_nonexistent_directory_returns_error() {
        let result = load_corpus(std::path::Path::new("/nonexistent/path/xyz"));
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_file_skipped_silently() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test_positive.ts"), "").unwrap();
        std::fs::write(dir.path().join("test_negative.ts"), "").unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert!(patterns.is_empty(), "Empty files should be skipped");
    }

    #[test]
    fn test_no_function_body_skipped_silently() {
        let dir = tempfile::tempdir().unwrap();
        // Type declaration only — no function body
        std::fs::write(
            dir.path().join("test_positive.ts"),
            "interface Config { host: string; }",
        )
        .unwrap();
        std::fs::write(dir.path().join("test_negative.ts"), "type Foo = string;").unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert!(
            patterns.is_empty(),
            "Files without functions should be skipped"
        );
    }

    #[test]
    fn test_bad_syntax_skipped_silently() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad_positive.ts"), "fn {{{ broken").unwrap();
        std::fs::write(dir.path().join("bad_negative.ts"), "fn {{{ broken").unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert!(
            patterns.is_empty(),
            "Files with bad syntax should be skipped"
        );
    }

    #[test]
    fn test_unsupported_extension_skipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test_positive.xyz"), "def foo(): pass").unwrap();
        std::fs::write(dir.path().join("test_negative.xyz"), "def bar(): pass").unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert!(
            patterns.is_empty(),
            "Unsupported extensions should be skipped"
        );
    }

    #[test]
    fn test_only_positive_no_warning_no_crash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("solo_positive.ts"),
            "function foo() { return 1; }",
        )
        .unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert!(
            patterns.is_empty(),
            "Positive-only should not produce a pattern"
        );
    }

    #[test]
    fn test_only_negative_no_warning_no_crash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("solo_negative.ts"),
            "function bar() { return 2; }",
        )
        .unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert!(
            patterns.is_empty(),
            "Negative-only should not produce a pattern"
        );
    }

    #[test]
    fn test_non_function_files_ignored() {
        let dir = tempfile::tempdir().unwrap();
        // Files without _positive/_negative in name should be ignored
        std::fs::write(dir.path().join("readme.md"), "hello").unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_parse_frensense_block_rust() {
        let source = r"/// [frensense]
/// observation: Function always returns true regardless of input.
/// impact: Malicious input passes validation unchecked.
/// improvement: Branch on input and return false for invalid values.
fn validate(input: &str) -> bool {
    true
}";
        let advisory = parse_frensense_block(source);
        assert_eq!(
            advisory.observation.as_deref(),
            Some("Function always returns true regardless of input.")
        );
        assert_eq!(
            advisory.impact.as_deref(),
            Some("Malicious input passes validation unchecked.")
        );
        assert_eq!(
            advisory.improvement.as_deref(),
            Some("Branch on input and return false for invalid values.")
        );
    }

    #[test]
    fn test_parse_frensense_block_typescript() {
        let source = "// [frensense]\n// observation: sanitize returns input unchanged.\n// impact: XSS payload passes through.\n// improvement: HTML-escape entities.\n";
        let advisory = parse_frensense_block(source);
        assert_eq!(
            advisory.observation.as_deref(),
            Some("sanitize returns input unchanged.")
        );
        assert_eq!(
            advisory.impact.as_deref(),
            Some("XSS payload passes through.")
        );
        assert_eq!(
            advisory.improvement.as_deref(),
            Some("HTML-escape entities.")
        );
    }

    #[test]
    fn test_parse_frensense_block_python() {
        let source = "# [frensense]\n# observation: No rejection on invalid token.\n# impact: Auth bypass.\n# improvement: Return None on failure.\n";
        let advisory = parse_frensense_block(source);
        assert_eq!(
            advisory.observation.as_deref(),
            Some("No rejection on invalid token.")
        );
        assert_eq!(advisory.impact.as_deref(), Some("Auth bypass."));
        assert_eq!(
            advisory.improvement.as_deref(),
            Some("Return None on failure.")
        );
    }

    #[test]
    fn test_parse_frensense_block_blank_line_ends() {
        let source = "/// [frensense]\n/// observation: Bug here.\n\n/// impact: Overwritten.\n";
        let advisory = parse_frensense_block(source);
        assert_eq!(advisory.observation.as_deref(), Some("Bug here."));
        assert_eq!(advisory.impact, None, "blank line should end the block");
    }

    #[test]
    fn test_parse_frensense_block_no_block() {
        let source = "fn foo() { return 1; }";
        let advisory = parse_frensense_block(source);
        assert!(advisory.observation.is_none());
        assert!(advisory.impact.is_none());
        assert!(advisory.improvement.is_none());
    }

    #[test]
    fn test_parse_frensense_block_partial() {
        let source = "/// [frensense]\n/// observation: Only observation provided.\n";
        let advisory = parse_frensense_block(source);
        assert_eq!(
            advisory.observation.as_deref(),
            Some("Only observation provided.")
        );
        assert!(advisory.impact.is_none());
        assert!(advisory.improvement.is_none());
    }

    #[test]
    fn test_valid_pair_loads_correctly() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rust_foo_positive.rs"),
            "fn foo() -> i32 { 1 }",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("rust_foo_negative.rs"),
            "fn foo() -> i32 { 2 }",
        )
        .unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].id, "rust_foo");
        assert!(!patterns[0].positives.is_empty());
        assert!(!patterns[0].negatives.is_empty());
    }

    #[test]
    fn test_multi_function_positive_loads_all() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rust_multi_positive.rs"),
            "fn a() { panic!(\"x\"); }\nfn b() { panic!(\"y\"); }\nfn c() { panic!(\"z\"); }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("rust_multi_negative.rs"),
            "fn a() -> Result<(), String> { Ok(()) }\nfn b() -> Result<(), String> { Ok(()) }\n",
        )
        .unwrap();
        let patterns = load_corpus(dir.path()).unwrap().0;
        assert_eq!(patterns.len(), 1);
        assert_eq!(
            patterns[0].positives.len(),
            3,
            "should extract all 3 functions from positive"
        );
        assert_eq!(
            patterns[0].negatives.len(),
            2,
            "should extract all 2 functions from negative"
        );
    }
}
