fn main() {
    let bundle = std::fs::read("frensense-corpus.frc").unwrap();
    let mut registry = frensense_engine::corpus::registry::PatternRegistry::new(0.4, 0.4, 0.4);
    registry.load_from_bundle(&bundle).unwrap();
    if let Some(auto) = registry.auto_filter_stats {
        if let Some(calls) = auto.contains_call_to.get("CORPUS_TS_RCE_VM_CONTEXT") {
            println!("CORPUS_TS_RCE_VM_CONTEXT required calls: {:?}", calls);
        }
        if let Some(nodes) = auto.contains_node_type.get("CORPUS_TS_RCE_VM_CONTEXT") {
            println!("CORPUS_TS_RCE_VM_CONTEXT required nodes: {:?}", nodes);
        }
    }
}
