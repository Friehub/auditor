// SPDX-License-Identifier: MIT

use rustc_hash::FxHashMap;

#[derive(Debug, Clone)]
pub struct PropagatorRule {
    pub name: String,
    pub tainted_arg: Option<usize>,
    pub tainted_receiver: bool,
    pub taints_return: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PropagatorRegistry {
    rules: FxHashMap<String, PropagatorRule>,
}

impl PropagatorRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            rules: FxHashMap::default(),
        };
        registry.load_builtins();
        registry
    }

    /// Create a registry using the language spec's propagator rules.
    /// When a spec is available, only spec-defined rules are loaded (the
    /// hardcoded builtins are skipped). When no spec is provided, falls
    /// back to `new()` which loads the JS/TS/Rust builtins.
    pub fn from_spec(spec: &dyn frensense_lang::LanguageSpec) -> Self {
        let mut registry = Self {
            rules: FxHashMap::default(),
        };
        registry.load_from_spec(spec);
        registry
    }

    fn add(&mut self, name: &str, arg: Option<usize>, receiver: bool) {
        self.rules.insert(
            name.to_string(),
            PropagatorRule {
                name: name.to_string(),
                tainted_arg: arg,
                tainted_receiver: receiver,
                taints_return: true,
            },
        );
    }

    fn load_builtins(&mut self) {
        // Identity
        self.add("JSON.parse", Some(0), false);
        self.add("Buffer.from", Some(0), false);
        self.add("atob", Some(0), false);
        self.add("btoa", Some(0), false);
        self.add("decodeURIComponent", Some(0), false);
        self.add("decodeURI", Some(0), false);
        self.add("JSON.stringify", Some(0), false);
        self.add("String", Some(0), false);
        self.add("Object.assign", Some(1), false);
        self.add("Object.create", Some(0), false);
        self.add("structuredClone", Some(0), false);

        // Array Methods (indexed by property name)
        self.add("map", None, true);
        self.add("filter", None, true);
        self.add("reduce", None, true);
        self.add("find", None, true);
        self.add("flatMap", None, true);
        self.add("Array.from", Some(0), false);
        self.add("join", None, true);
        self.add("slice", None, true);
        self.add("concat", None, true);
        self.add("flat", None, true);

        // String Methods (indexed by property name)
        self.add("replace", None, true);
        self.add("replaceAll", None, true);
        self.add("substring", None, true);
        self.add("split", None, true);
        self.add("trim", None, true);
        self.add("toLowerCase", None, true);
        self.add("toUpperCase", None, true);
        self.add("padStart", None, true);
        self.add("padEnd", None, true);

        // Object Methods
        self.add("Object.keys", Some(0), false); // Often passed object, but if called on object it's handled differently. Wait, Object.keys(obj) is arg 0.
        self.add("Object.values", Some(0), false);
        self.add("Object.entries", Some(0), false);
        self.add("Object.fromEntries", Some(0), false);

        // Promise Methods
        self.add("Promise.resolve", Some(0), false);
        self.add("Promise.all", Some(0), false);
        self.add("await", None, true); // Often handled at AST level, but good to have

        // Rust Methods
        self.add("to_string", None, true);
        self.add("clone", None, true);
    }

    pub fn load_from_spec(&mut self, spec: &dyn frensense_lang::LanguageSpec) {
        for rule in spec.propagator_rules() {
            self.rules.insert(
                rule.call.to_string(),
                PropagatorRule {
                    name: rule.call.to_string(),
                    tainted_arg: rule.tainted_arg,
                    tainted_receiver: rule.tainted_receiver,
                    taints_return: true,
                },
            );
        }
    }

    pub fn get_rule(&self, name: &str) -> Option<&PropagatorRule> {
        self.rules.get(name)
    }
}
