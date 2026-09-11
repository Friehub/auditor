use std::fs;
use tree_sitter::Parser;

#[test]
fn test_extracted_flows() {
    let source = fs::read_to_string("../corpus/targets/ts_n_plus_one_query_positive.ts").unwrap();
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .unwrap();
    let tree = parser.parse(&source, None).unwrap();

    let flows = frensense_engine::corpus::data_flow_extractor::extract_data_flows(
        tree.root_node(),
        &source,
        frensense_lang::spec_for_ext("ts"),
    );
    println!("EXTRACTED_FLOWS: {:#?}", flows);
    assert!(!flows.is_empty());
}
