#![allow(unused)]
#![allow(clippy::all)]
// SPDX-License-Identifier: MIT
#![warn(clippy::unwrap_used)]

use frensense::cli::{
    apply_filters, compare_baseline, find_profile, get_input_path, handle_early_args,
    handle_remediation, parse_options, print_profile_stats, print_results, save_baseline,
};
use frensense::parser::ParserRegistry;
use frensense::{Engine, Result};
use serde_json;
use std::env;
use std::path::PathBuf;

const CORPUS_BUNDLE: &[u8] = include_bytes!("../../frensense-corpus.frc");

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .init();
    // nosemgrep: rust.lang.security.args.args
    let args: Vec<String> = env::args().collect();
    if handle_early_args(&args) {
        return Ok(());
    }

    let input_path = get_input_path(&args);
    let options = parse_options(&args);

    // Handle build-bundle
    if options.build_bundle.is_yes() {
        let corpus_dir = options
            .corpus_dir
            .clone()
            .unwrap_or_else(|| input_path.clone());
        let output_path = options
            .build_bundle_output
            .clone()
            .unwrap_or_else(|| PathBuf::from("frensense-corpus.frc"));

        eprintln!("Building FRC bundle from {}...", corpus_dir.display());
        match frensense_bundler::builder::build_bundle(&corpus_dir) {
            Ok(bytes) => {
                std::fs::write(&output_path, &bytes)?;
                eprintln!(
                    "Successfully built {} ({} bytes)",
                    output_path.display(),
                    bytes.len()
                );
                return Ok(());
            }
            Err(e) => {
                eprintln!("Error building bundle: {e}");
                std::process::exit(1);
            }
        }
    }

    // Handle learn mode
    if options.learn_mode.is_yes() {
        handle_learn_mode(&options);
        return Ok(());
    }

    let mut engine = Engine::new();
    engine.set_corpus_bundle(CORPUS_BUNDLE);
    engine.set_suite(options.suite);
    engine.set_severity_filter(options.severity_filter);

    if let Some(val) = options.jaccard_threshold {
        engine.set_jaccard_threshold(val);
    }
    if let Some(val) = options.confidence_boost_rate {
        engine.set_confidence_boost_rate(val);
    }
    if let Some(val) = options.confidence_boost_max {
        engine.set_confidence_boost_max(val);
    }
    if let Some(val) = options.max_source_lines {
        engine.set_max_source_lines(val);
    }
    if let Some(val) = options.ngram_window_size {
        engine.set_ngram_window_size(val);
    }
    if let Some(val) = options.min_ngram_count {
        engine.set_min_ngram_count(val);
    }
    if let Some(val) = options.taint_confidence_interprocedural {
        engine.set_taint_confidence_interprocedural(val);
    }
    if let Some(val) = options.taint_confidence_intraprocedural {
        engine.set_taint_confidence_intraprocedural(val);
    }
    if let Some(val) = options.default_taint_max_depth {
        engine.set_default_taint_max_depth(val);
    }

    for rule_id in &options.disabled_rules {
        engine.add_disabled_rule(rule_id);
    }
    for (rule_id, severity) in &options.severity_overrides {
        engine.add_severity_override(rule_id, *severity);
    }

    if let Some(ref corpus_dir) = options.corpus_dir {
        engine.set_corpus_dir(corpus_dir.clone());
    }
    engine.set_corpus_threshold(options.corpus_threshold);
    if !options.threshold_overrides.is_empty() {
        engine.set_threshold_overrides(options.threshold_overrides.clone());
    }
    if let Some(ref baseline_path) = options.baseline_path {
        engine.set_baseline_path(baseline_path.clone());
    }
    if !options.extra_taint_rule_dirs.is_empty() {
        engine.set_extra_taint_rule_dirs(options.extra_taint_rule_dirs.clone());
    }
    if options.check_deps.is_yes() {
        engine.set_check_deps(true);
    }
    engine.set_use_data_flow(options.scan_mode == "taint" || options.scan_mode == "taint-only");
    engine.set_use_taint_only(options.scan_mode == "taint-only");
    engine.set_use_compiler(options.use_compiler);

    if let Some(val) = options.ngram_sim_threshold {
        engine.set_ngram_sim_threshold(val);
    }

    // Apply scorer configuration from CLI flags
    if let Some(val) = options.scorer_cross_lingual_penalty {
        engine.set_scorer_cross_lingual_penalty(val);
    }
    if let Some(val) = options.scorer_semantic_zero_penalty {
        engine.set_scorer_semantic_zero_penalty(val);
    }
    if let Some(val) = options.scorer_semantic_match_boost {
        engine.set_scorer_semantic_match_boost(val);
    }
    if let Some(val) = options.scorer_noise_gate_moderate {
        engine.set_scorer_noise_gate_moderate(val);
    }
    if let Some(val) = options.scorer_noise_gate_strong {
        engine.set_scorer_noise_gate_strong(val);
    }
    if let Some(val) = options.scorer_neg_penalty_floor {
        engine.set_scorer_neg_penalty_floor(val);
    }
    if let Some(val) = options.scorer_neg_penalty_weight {
        engine.set_scorer_neg_penalty_weight(val);
    }
    if let Some(val) = options.scorer_context_mismatch_penalty {
        engine.set_scorer_context_mismatch_penalty(val);
    }

    // Apply taint/verification configuration
    if let Some(val) = options.taint_verified_boost {
        engine.set_taint_verified_boost(val);
    }
    if let Some(val) = options.cross_file_taint_boost {
        engine.set_cross_file_taint_boost(val);
    }
    if let Some(val) = options.taint_boost_cap {
        engine.set_taint_boost_cap(val);
    }
    if let Some(val) = options.score_suppression_floor {
        engine.set_score_suppression_floor(val);
    }

    // Apply LSH configuration
    if let Some(val) = options.lsh_num_hashes {
        engine.set_lsh_num_hashes(val);
    }
    if let Some(val) = options.lsh_bands {
        engine.set_lsh_bands(val);
    }
    if let Some(val) = options.lsh_rows_per_band {
        engine.set_lsh_rows_per_band(val);
    }

    // Apply fingerprinting configuration
    if let Some(ref val) = options.ngram_windows {
        let windows: Vec<usize> = val
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        if !windows.is_empty() {
            engine.set_ngram_windows(windows);
        }
    }
    if let Some(val) = options.cf_max_depth {
        engine.set_cf_max_depth(val);
    }

    if let Some(lang_arg) = &options.language_filter {
        if let Some(exts) = frensense::parser::ParserRegistry::extensions_for(lang_arg) {
            engine.set_language_filter(exts);
        } else {
            eprintln!(
                "Error: Unknown language '{lang_arg}'. Supported values: rust, typescript/ts, javascript/js, python/py, yaml"
            );
            std::process::exit(1);
        }
    }

    #[cfg(feature = "fingerprinting")]
    if options.learn_profile.is_yes() {
        let mut all_fingerprints = Vec::new();
        let files = Engine::collect_files(&input_path, None);
        let wsize = options.ngram_window_size.unwrap_or(5);
        for p in &files {
            if let Ok(content) = std::fs::read_to_string(p) {
                let mut fps = Vec::new();
                if let Ok((_language, tree)) = engine.auditor().parse_source(p, &content) {
                    frensense_engine::fingerprint::extract_fingerprints(
                        tree.root_node(),
                        &content,
                        p,
                        &mut fps,
                        wsize,
                        None,
                    );
                    all_fingerprints.extend(fps);
                }
            }
        }
        let profile = frensense_engine::profile::ProjectProfile::learn(&all_fingerprints);
        let profile_dir = if input_path.is_file() {
            input_path.parent().unwrap_or(&input_path)
        } else {
            &input_path
        };
        let profile_path = profile_dir.join(".frensense").join("profile.json");
        profile.save(&profile_path)?;
        println!(
            "[OK] Profile learned and saved to {}",
            profile_path.display()
        );
        if options.profile_stats.is_yes() {
            print_profile_stats(&profile);
        }
        return Ok(());
    }

    #[cfg(feature = "fingerprinting")]
    if options.check_profile.is_yes() {
        let profile_path = find_profile(&input_path)
            .unwrap_or_else(|| input_path.join(".frensense").join("profile.json"));
        if !profile_path.exists() {
            eprintln!(
                "Error: No profile found at {}. Run `frensense --learn-profile` first.",
                profile_path.display()
            );
            std::process::exit(1);
        }
        let profile =
            frensense_engine::profile::ProjectProfile::load(&profile_path).map_err(|e| {
                frensense::FrensenseError::Config(format!("Failed to load profile: {e}"))
            })?;
        if let Some(threshold) = options.profile_threshold {
            engine.set_profile_threshold(threshold);
        }
        engine = engine.with_profile(profile);
        if options.profile_stats.is_yes()
            && let Some(profile) = engine.profile()
        {
            print_profile_stats(profile);
        }
    }

    #[cfg(feature = "fingerprinting")]
    if options.profile_stats.is_yes()
        && !options.learn_profile.is_yes()
        && !options.check_profile.is_yes()
    {
        let profile_path = find_profile(&input_path)
            .unwrap_or_else(|| input_path.join(".frensense").join("profile.json"));
        if profile_path.exists() {
            let profile =
                frensense_engine::profile::ProjectProfile::load(&profile_path).map_err(|e| {
                    frensense::FrensenseError::Config(format!("Failed to load profile: {e}"))
                })?;
            print_profile_stats(&profile);
        } else {
            eprintln!("No profile found at {}.", profile_path.display());
        }
        return Ok(());
    }

    let mut filtered_advisories = if options.diff_only.is_yes() {
        let repo_dir = if input_path.is_dir() {
            input_path.clone()
        } else {
            input_path.parent().unwrap_or(&input_path).to_path_buf()
        };
        let output = std::process::Command::new("git")
            .arg("diff")
            .arg("--name-only")
            .arg("HEAD")
            .current_dir(&repo_dir)
            .output()
            .map_err(|e| {
                frensense::FrensenseError::Config(format!(
                    "Failed to run git diff: {e} - is this a git repository?"
                ))
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(frensense::FrensenseError::Config(format!(
                "git diff failed: {stderr}"
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let diff_files: Vec<PathBuf> = stdout
            .lines()
            .map(|l| repo_dir.join(l))
            .filter(|p| ParserRegistry::is_supported(p))
            .filter(|p| {
                if let Some(ref lang) = options.language_filter {
                    let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
                    frensense::parser::ParserRegistry::extensions_for(lang)
                        .is_some_and(|exts| exts.contains(&ext))
                } else {
                    true
                }
            })
            .collect();

        if diff_files.is_empty() {
            eprintln!("No changed files to scan.");
            Vec::new()
        } else {
            eprintln!(
                "Diff-only: scanning {} changed file(s)...",
                diff_files.len()
            );
            engine.run_files(&input_path, &diff_files)?
        }
    } else {
        engine.run(&input_path)?
    };
    apply_filters(&mut filtered_advisories, &options, &engine);

    // Mine negative candidates from grey-zone findings
    if options.mine_negatives {
        let mine_dir = std::path::Path::new(&options.mine_negatives_dir);
        match frensense::engine::negative_miner::mine_negatives(
            &filtered_advisories,
            mine_dir,
            options.min_confidence,
        ) {
            Ok(count) if count > 0 => {
                eprintln!(
                    "Mined {count} negative candidates in {}",
                    mine_dir.display()
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!("Error mining negatives: {e}"),
        }
    }

    print_results(&filtered_advisories, &options.format, &input_path)?;

    if options.emit_hypotheses {
        let hypotheses_path = input_path.join("hypotheses.json");
        let json = serde_json::to_string_pretty(&filtered_advisories).map_err(|e| {
            frensense::FrensenseError::Config(format!("JSON serialization error: {e}"))
        })?;
        std::fs::write(&hypotheses_path, &json).map_err(|e| {
            frensense::FrensenseError::Config(format!("Failed to write hypotheses: {e}"))
        })?;
        eprintln!("Wrote hypotheses to {}", hypotheses_path.display());
    }

    if let Some(path) = &options.emit_baseline_path {
        save_baseline(&filtered_advisories, path)?;
    }

    let mut regression_detected = false;
    if let Some(path) = &options.compare_baseline_path {
        regression_detected = compare_baseline(&filtered_advisories, path)?;
    }

    if (options.fix_scope.is_some() || options.diff_scope.is_some())
        && !filtered_advisories.is_empty()
    {
        handle_remediation(&filtered_advisories, &options, &input_path);
    }

    if regression_detected || (options.is_strict.is_yes() && !filtered_advisories.is_empty()) {
        std::process::exit(1);
    }

    Ok(())
}

fn handle_learn_mode(options: &frensense::cli::CliOptions) {
    let positive_path = if let Some(p) = options.learn_positive.as_ref() {
        p.clone()
    } else {
        eprintln!("Error: --learn requires a positive (buggy) file");
        std::process::exit(1);
    };

    let negative_path = if let Some(p) = options.learn_negative.as_ref() {
        p.clone()
    } else {
        eprintln!("Error: --learn requires a negative (fixed) file");
        std::process::exit(1);
    };

    // Generate pattern ID from filename
    let pattern_id = positive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("learned_pattern")
        .replace("_positive", "");

    let output_dir = options
        .learn_output
        .clone()
        .unwrap_or_else(|| PathBuf::from("learned_rules"));

    eprintln!("Learning pattern: {pattern_id}");
    eprintln!("  Positive: {}", positive_path.display());
    eprintln!("  Negative: {}", negative_path.display());
    eprintln!();

    match frensense::engine::learn::learn_pattern(
        &positive_path,
        &negative_path,
        &pattern_id,
        &output_dir,
    ) {
        Ok(result) => {
            eprintln!("Learned pattern: {}", result.pattern_id);
            eprintln!("  Positive functions: {}", result.positive_functions);
            eprintln!("  Negative functions: {}", result.negative_functions);
            eprintln!("  Metadata: {}", result.metadata_path.display());
            eprintln!();

            // Show diff summary
            eprintln!("Diff Summary:");
            eprintln!("{}", result.diff_summary);

            // Show learned patterns
            if !result.learned_patterns.is_empty() {
                eprintln!("Learned {} pattern(s):", result.learned_patterns.len());
                for pattern in &result.learned_patterns {
                    eprintln!(
                        "  - {:?}: {} in {}",
                        pattern.kind, pattern.description, pattern.function
                    );
                }
            }

            // Generate taint rules from metadata
            let taint_rules =
                frensense::engine::learn::load_learned_taint_rules(&result.metadata_path);
            eprintln!("Found {} taint rule(s) in metadata", taint_rules.len());
            if !taint_rules.is_empty() {
                let taint_path = output_dir.join("learned_taint.toml");
                let mut taint_toml =
                    String::from("# Auto-generated taint rules from pattern learning\n\n");
                for rule in &taint_rules {
                    taint_toml.push_str(&rule.to_toml());
                }
                std::fs::write(&taint_path, &taint_toml).ok();
                eprintln!();
                eprintln!("Generated taint rules: {}", taint_path.display());
            }

            eprintln!();
            eprintln!("Next steps:");
            eprintln!("  1. Rebuild bundle:");
            eprintln!("     frensense --build-bundle corpus/targets/");
            eprintln!();
            eprintln!("  2. Or scan with learned rules:");
            eprintln!(
                "     frensense . --extra-taint-rules {}",
                output_dir.display()
            );
        }
        Err(e) => {
            eprintln!("Error learning pattern: {e}");
            std::process::exit(1);
        }
    }
}
