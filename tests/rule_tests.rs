// SPDX-License-Identifier: MIT

use frensense::engine::project::Engine;
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join("targets")
}

fn corpus_file(name: &str) -> String {
    let path = corpus_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

fn run_test(rule_id: &str, content: &str, expect_match: bool, ext: &str) {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join(format!("test.{ext}"));
    std::fs::write(&file_path, content).unwrap();

    let mut engine = Engine::new();
    engine.set_corpus_dir(corpus_dir());
    engine.set_corpus_threshold(0.32);
    let advisories = engine.run(dir.path()).unwrap();

    let rule_findings: Vec<_> = advisories.iter().filter(|a| a.rule_id == rule_id).collect();
    if expect_match {
        assert!(
            !rule_findings.is_empty(),
            "Rule {} expected >=1 findings but got 0. Content preview: {}",
            rule_id,
            &content[..content.len().min(80)]
        );
    } else {
        assert_eq!(
            rule_findings.len(),
            0,
            "Rule {} expected 0 findings but got {}. Content preview: {}",
            rule_id,
            rule_findings.len(),
            &content[..content.len().min(80)]
        );
    }
}

fn corpus_rule_id(pattern_name: &str) -> String {
    format!("CORPUS_{}", pattern_name.to_uppercase())
}

#[test]
#[ignore = "missing corpus data or needs enrichment"]
fn test_rust_panic_in_lib() {
    let rule_id = corpus_rule_id("rust_panic_in_lib");
    run_test(
        &rule_id,
        &corpus_file("rust_panic_in_lib_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_panic_in_lib_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_rust_blocking_io() {
    let rule_id = corpus_rule_id("rust_async_blocking_io");
    run_test(
        &rule_id,
        &corpus_file("rust_async_blocking_io_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_async_blocking_io_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data or needs enrichment"]
fn test_rust_clone_in_loop() {
    let rule_id = corpus_rule_id("rust_clone_in_loop");
    run_test(
        &rule_id,
        &corpus_file("rust_clone_in_loop_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_clone_in_loop_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_rust_connection_leak() {
    let rule_id = corpus_rule_id("rust_connection_leak");
    run_test(
        &rule_id,
        &corpus_file("rust_connection_leak_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_connection_leak_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_rust_network_in_txn() {
    let rule_id = corpus_rule_id("rust_network_in_txn");
    run_test(
        &rule_id,
        &corpus_file("rust_network_in_txn_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_network_in_txn_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_rust_mutate_after_response() {
    let rule_id = corpus_rule_id("rust_mutate_after_response");
    run_test(
        &rule_id,
        &corpus_file("rust_mutate_after_response_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_mutate_after_response_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_rust_transmute() {
    let rule_id = corpus_rule_id("rust_transmute");
    run_test(
        &rule_id,
        &corpus_file("rust_transmute_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_transmute_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "multi-example scoring: negative too similar - needs Phase 1 enrichment"]
fn test_rust_csa_validate_unconditional() {
    let rule_id = corpus_rule_id("rust_csa_validate_unconditional");
    run_test(
        &rule_id,
        &corpus_file("rust_csa_validate_unconditional_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_csa_validate_unconditional_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_rust_llm_clone_literal() {
    let rule_id = corpus_rule_id("rust_llm_clone_literal");
    run_test(
        &rule_id,
        &corpus_file("rust_llm_clone_literal_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_llm_clone_literal_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data or needs enrichment"]
fn test_rust_llm_await_in_sync() {
    let rule_id = corpus_rule_id("rust_llm_await_in_sync");
    run_test(
        &rule_id,
        &corpus_file("rust_llm_await_in_sync_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_llm_await_in_sync_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data or needs enrichment"]
fn test_rust_llm_never_err() {
    let rule_id = corpus_rule_id("rust_llm_never_err");
    run_test(
        &rule_id,
        &corpus_file("rust_llm_never_err_positive.rs"),
        true,
        "rs",
    );
    run_test(
        &rule_id,
        &corpus_file("rust_llm_never_err_negative.rs"),
        false,
        "rs",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_ts_command_injection() {
    let rule_id = corpus_rule_id("ts_command_injection");
    run_test(
        &rule_id,
        &corpus_file("ts_command_injection_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_command_injection_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "missing corpus data or needs enrichment"]
fn test_ts_cookie_security() {
    let rule_id = corpus_rule_id("ts_cookie_security");
    run_test(
        &rule_id,
        &corpus_file("ts_cookie_security_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_cookie_security_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "multi-example scoring: negative too similar - needs Phase 1 enrichment"]
fn test_ts_as_any_escape() {
    let rule_id = corpus_rule_id("ts_as_any_escape");
    run_test(
        &rule_id,
        &corpus_file("ts_as_any_escape_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_as_any_escape_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_ts_csa_validate_unconditional() {
    let rule_id = corpus_rule_id("ts_csa_validate_unconditional");
    run_test(
        &rule_id,
        &corpus_file("ts_csa_validate_unconditional_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_csa_validate_unconditional_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_ts_csa_auth_no_rejection() {
    let rule_id = corpus_rule_id("ts_csa_auth_no_rejection");
    run_test(
        &rule_id,
        &corpus_file("ts_csa_auth_no_rejection_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_csa_auth_no_rejection_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "multi-example scoring: negative too similar - needs Phase 1 enrichment"]
fn test_ts_csa_sanitize_passthrough() {
    let rule_id = corpus_rule_id("ts_csa_sanitize_passthrough");
    run_test(
        &rule_id,
        &corpus_file("ts_csa_sanitize_passthrough_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_csa_sanitize_passthrough_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "multi-example scoring: negative too similar - needs Phase 1 enrichment"]
fn test_ts_csa_find_never_empty() {
    let rule_id = corpus_rule_id("ts_csa_find_never_empty");
    run_test(
        &rule_id,
        &corpus_file("ts_csa_find_never_empty_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_csa_find_never_empty_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "missing corpus data or needs enrichment"]
fn test_ts_hardcoded_secret() {
    let rule_id = corpus_rule_id("ts_hardcoded_secret");
    run_test(
        &rule_id,
        &corpus_file("ts_hardcoded_secret_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_hardcoded_secret_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_ts_llm_any_parameter() {
    let rule_id = corpus_rule_id("ts_llm_any_parameter");
    run_test(
        &rule_id,
        &corpus_file("ts_llm_any_parameter_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_llm_any_parameter_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "multi-example scoring: negative too similar - needs Phase 1 enrichment"]
fn test_ts_llm_promise_catch() {
    let rule_id = corpus_rule_id("ts_llm_promise_catch");
    run_test(
        &rule_id,
        &corpus_file("ts_llm_promise_catch_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_llm_promise_catch_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "missing corpus data"]
fn test_ts_llm_console_log() {
    let rule_id = corpus_rule_id("ts_llm_console_log");
    run_test(
        &rule_id,
        &corpus_file("ts_llm_console_log_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_llm_console_log_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "missing corpus data or needs enrichment"]
fn test_ts_llm_mutate_after_response() {
    let rule_id = corpus_rule_id("ts_llm_mutate_after_response");
    run_test(
        &rule_id,
        &corpus_file("ts_llm_mutate_after_response_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_llm_mutate_after_response_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "multi-example scoring: negative too similar - needs Phase 1 enrichment"]
fn test_ts_prototype_pollution() {
    let rule_id = corpus_rule_id("ts_prototype_pollution");
    run_test(
        &rule_id,
        &corpus_file("ts_prototype_pollution_positive.ts"),
        true,
        "ts",
    );
    run_test(
        &rule_id,
        &corpus_file("ts_prototype_pollution_negative.ts"),
        false,
        "ts",
    );
}

#[test]
#[ignore = "multi-example scoring: negative too similar - needs Phase 1 enrichment"]
fn test_ts_ssrf_vulnerability() {
    let rule_id = corpus_rule_id("ts_ssrf");
    run_test(&rule_id, &corpus_file("ts_ssrf_positive.ts"), true, "ts");
    run_test(&rule_id, &corpus_file("ts_ssrf_negative.ts"), false, "ts");
}
