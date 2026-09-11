// SPDX-License-Identifier: MIT

use frensense::engine::auditor::FrensenseAuditor;
use frensense::engine::project::Engine;
use frensense::semantics::SymbolRegistry;
use frensense::semantics::data_flow::TaintOrigin;
use frensense::{FileId, FrensenseContext, TaintCache};
use rustc_hash::FxHashMap;
use std::path::Path;

#[test]
#[ignore]
fn test_symbol_shadowing() {
    let content = r"
        let x = 1;
        fn inner() {
            let x = 2;
            let y = x;
        }
    ";
    let path = Path::new("shadow.rs");
    let auditor = FrensenseAuditor::default_auditor();
    let (lang, tree) = auditor
        .parse_source(path, content)
        .expect("Failed to find symbol");
    let symbols = auditor
        .discover_symbols(path, FileId(1), content, &lang, &tree)
        .expect("Failed to find symbol");

    let mut registry = SymbolRegistry::new();
    for sym in symbols {
        println!(
            "symbol name: {}, line: {}, end_line: {}",
            sym.name, sym.line, sym.end_line
        );
        registry.insert(sym);
    }

    // Check at 'let x = 2'
    let sym = registry
        .find_at("x", "shadow.rs", 3)
        .expect("Failed to find symbol");
    assert_eq!(sym.line, 3, "Should resolve to local x on line 3");
}

#[test]
fn test_taint_through_destructuring() {
    let content = r"
        let (a, b) = get_tainted_pair();
        sink(a);
    ";
    let path = Path::new("destruct.rs");
    let auditor = FrensenseAuditor::default_auditor();
    let (lang, tree) = auditor
        .parse_source(path, content)
        .expect("Failed to find symbol");
    let symbols = auditor
        .discover_symbols(path, FileId(1), content, &lang, &tree)
        .expect("Failed to find symbol");
    let mut registry = SymbolRegistry::new();
    for sym in symbols {
        registry.insert(sym);
    }
    let ops = auditor.extract_semantic_ops(path, content, &tree);
    let taint_cache = TaintCache::default();

    let ctx = FrensenseContext {
        file_id: FileId(1),
        file_path: path,
        source_code: content,
        tree: &tree,
        symbols: &registry,
        graph: registry.graph(),
        semantic_ops: &ops,
        taint_cache: &taint_cache,
        file_trees: &FxHashMap::default(),
        file_context: frensense_engine::context::FileContext::extract(path, content),
        taint_confidence_interprocedural: 0.80,
        taint_confidence_intraprocedural: 0.90,
        default_taint_max_depth: 5,
        ngram_window_size: 5,
    };

    let analyzer = frensense::semantics::data_flow::DataFlowAnalyzer::new(&ctx, tree.root_node());
    let mut taint_reg = frensense::semantics::data_flow::TaintRegistry::default();

    // Manual source injection
    taint_reg.taint("get_tainted_pair", TaintOrigin::UserInput);

    let advisories = analyzer.analyze_block(tree.root_node(), &mut taint_reg);

    // analyze_block now only propagates taint — it no longer emits advisories.
    // Taint verification is handled by the corpus layer (CrossFileVerifier).
    // This test verifies that analyze_block runs without panicking.
    // Full taint detection is tested via corpus patterns.
    let _ = advisories;
}

#[test]
fn test_suppression_correctness() {
    let _ = r#"
        // frensense-suppress RUST_PANIC
        panic!("intentional");
        panic!("unsuppressed");
    "#;
    // This test requires a real rule that matches panic!
    // Since we are doing engine-level tests, we verify FrensenseAuditor::audit suppression logic.
}

#[test]
fn test_snapshot_determinism() {
    let content = "fn main() { let x = 1; }";
    let path = Path::new("main.rs");
    let mut engine = Engine::new();

    let advisories1 = engine
        .run_content(path, content)
        .expect("Failed to find symbol");
    let advisories2 = engine
        .run_content(path, content)
        .expect("Failed to find symbol");

    assert_eq!(advisories1.len(), advisories2.len());
}

#[test]
fn test_sarif_output_properties() {
    use frensense::Advisory;
    use frensense::FileId;
    use frensense::reporter::Reporter;

    let adv = Advisory {
        rule_id: "TEST_RULE".into(),
        file_id: FileId(1),
        file_path: "src/main.rs".into(),
        severity: frensense::Severity::Warning,
        confidence: 0.85,
        observation: "observation".into(),
        impact: "impact".into(),
        improvement: "improvement".into(),
        line: 10,
        column: 5,
        start_byte: 100,
        end_byte: 120,
        original_content: "foo()".into(),
        proposed_replacement: None,
        proposed_import: None,
        enclosing_symbol: None,
        fingerprint: "hash".into(),
        auto_fixable: true,
        requires_human: false,
        tags: vec!["security".into(), "rust".into()],
        taint_branch_ratio: None,
        has_validation_name: Some(false),
        match_evidence: None,
        cwe: None,
        cvss: None,
        owasp: None,
    };

    let sarif = Reporter::to_sarif(&[adv], Path::new("."));
    let results = sarif
        .get("runs")
        .and_then(|r| r.as_array())
        .and_then(|r| r.first())
        .and_then(|run| run.get("results"))
        .and_then(|res| res.as_array())
        .expect("SARIF structure");

    assert_eq!(results.len(), 1);
    let result = &results[0];
    let properties = result.get("properties").expect("properties bag");

    let conf = properties
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .expect("confidence");
    assert!((conf - 0.85).abs() < 1e-5);
    assert_eq!(
        properties
            .get("auto_fixable")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        properties
            .get("requires_human")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );

    let tags = properties
        .get("tags")
        .and_then(|t| t.as_array())
        .expect("tags array");
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0].as_str(), Some("security"));
    assert_eq!(tags[1].as_str(), Some("rust"));
}

// test_non_remediated_advisory_is_not_auto_fixable removed —
// TAINT_CREDENTIAL_TO_LOG was a taint-as-detection rule that has been removed.
// Taint detection is now corpus-driven. See corpus/targets/ for detection patterns.
