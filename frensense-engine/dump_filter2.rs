fn main() {
    let bundle = std::fs::read("frensense-corpus.frc").unwrap();
    let mut registry = frensense_engine::corpus::registry::PatternRegistry::new(0.4, 0.4, 0.4);
    registry.load_from_bundle(&bundle).unwrap();
    if let Some(auto) = registry.auto_filter_stats {
        if let Some(nodes) = auto
            .must_not_contain_node_type
            .get("CORPUS_TS_ROLE_HIERARCHY_BYPASS")
        {
            println!(
                "CORPUS_TS_ROLE_HIERARCHY_BYPASS forbidden nodes: {:?}",
                nodes
            );
        } else {
            println!("No forbidden nodes");
        }
    }
}
