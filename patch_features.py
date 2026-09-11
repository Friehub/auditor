import re

with open("frensense-bundler/src/loader/features.rs", "r") as f:
    code = f.read()

code = code.replace(
    'let pos_calls: Vec<&str> = pos_features\n        .iter()\n        .flat_map(|f| f.calls.iter().map(std::string::String::as_str))\n        .collect();',
    'let pos_calls: std::collections::HashSet<&str> = pos_features\n        .iter()\n        .flat_map(|f| f.calls.iter().map(std::string::String::as_str))\n        .collect();'
)

code = code.replace(
    'let neg_calls: Vec<&str> = neg_features\n        .iter()\n        .flat_map(|f| f.calls.iter().map(std::string::String::as_str))\n        .collect();',
    'let neg_calls: std::collections::HashSet<&str> = neg_features\n        .iter()\n        .flat_map(|f| f.calls.iter().map(std::string::String::as_str))\n        .collect();'
)

code = code.replace(
    'let pos_nts: Vec<&str> = pos_features\n        .iter()\n        .flat_map(|f| f.node_types.iter().map(std::string::String::as_str))\n        .collect();',
    'let pos_nts: std::collections::HashSet<&str> = pos_features\n        .iter()\n        .flat_map(|f| f.node_types.iter().map(std::string::String::as_str))\n        .collect();'
)

code = code.replace(
    'let neg_nts: Vec<&str> = neg_features\n        .iter()\n        .flat_map(|f| f.node_types.iter().map(std::string::String::as_str))\n        .collect();',
    'let neg_nts: std::collections::HashSet<&str> = neg_features\n        .iter()\n        .flat_map(|f| f.node_types.iter().map(std::string::String::as_str))\n        .collect();'
)

with open("frensense-bundler/src/loader/features.rs", "w") as f:
    f.write(code)

print("Patched features.rs")
