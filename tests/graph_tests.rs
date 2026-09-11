// SPDX-License-Identifier: MIT

use frensense::engine::Engine;
use tempfile::tempdir;

#[test]
#[ignore]
fn test_inter_procedural_call_graph() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("main.rs");

    let content = r#"
        fn main() {
            let user_input = get_input();
            process(user_input);
        }

        fn process(data: String) {
            danger(data);
        }

        fn danger(val: String) {
            println!("{}", val);
        }

        fn get_input() -> String {
            "untrusted".to_string()
        }
    "#;

    std::fs::write(&file_path, content).unwrap();

    let mut engine = Engine::new();

    // Run the engine
    let (_advisories, symbols) = engine.run_detailed(dir.path()).unwrap();

    // Verify Graph
    let graph = symbols.graph();

    let main_idx = graph.find_nodes("main")[0];
    let process_idx = graph.find_nodes("process")[0];
    let danger_idx = graph.find_nodes("danger")[0];
    let get_input_idx = graph.find_nodes("get_input")[0];

    // Check main -> process
    let main_neighbors = graph.neighbors_of(main_idx, frensense::semantics::graph::EdgeKind::Calls);
    assert!(
        main_neighbors.contains(&process_idx),
        "main should call process"
    );
    assert!(
        main_neighbors.contains(&get_input_idx),
        "main should call get_input"
    );

    // Check process -> danger
    let process_neighbors =
        graph.neighbors_of(process_idx, frensense::semantics::graph::EdgeKind::Calls);
    assert!(
        process_neighbors.contains(&danger_idx),
        "process should call danger"
    );

    println!("SUCCESS: Call graph verified!");
}
