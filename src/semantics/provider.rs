// SPDX-License-Identifier: MIT

//! Per-file selection of the semantic provider.
//!
//! The taint analysis needs to answer "is this parameter a source?" and "is
//! this call a sink?" for every file it verifies. There are three
//! implementations of `SemanticProvider`, chosen here:
//!
//! * `ImportMapProvider` (default) — tree-sitter name heuristics. This is the
//!   behavioural twin of the legacy inline `is_source_type` + name matching,
//!   so the default scan path is unchanged.
//! * `OxcProvider` — real TypeScript/JavaScript type resolution.
//! * `RustHirProvider` — rust-analyzer backed HIR types for Rust.
//!
//! The compiler-backed providers are only selected under `--use-compiler`
//! (`use_compiler`), which keeps a clean heuristics-vs-compiler benchmark.

use std::path::Path;
use std::sync::Arc;

use frensense_engine::context::Environment;
use frensense_engine::corpus::source_sink::CorpusSourceSinkRegistry;
use frensense_engine::import_resolver::ImportMap;
use frensense_engine::semantic::{ImportMapProvider, SemanticProvider};
use frensense_providers::oxc_provider::OxcProvider;
use tree_sitter::Tree;

#[cfg(feature = "rust-hir")]
use frensense_providers::rust_hir_provider::RustHirProvider;

/// Pre-built HIR map for the analysed workspace, or `()` when the `rust-hir`
/// feature is not compiled in. Keeping a single `RustHirMap` name lets the
/// runner thread this value through without cfg-splitting its signatures.
#[cfg(feature = "rust-hir")]
pub type RustHirMap = frensense_engine::semantic::HirTypeMap;
#[cfg(not(feature = "rust-hir"))]
pub type RustHirMap = ();

/// Pick the strongest provider available for `path`.
///
/// With `use_compiler`, TS/JS get the Oxc type resolver and Rust gets the
/// rust-analyzer HIR provider (when `rust_hir` was built). Everything else —
/// including all files when `use_compiler` is off — falls back to the
/// import-map heuristics.
#[must_use]
#[allow(unused_variables)]
pub fn per_file_provider(
    source: &str,
    tree: &Tree,
    path: &Path,
    source_sink: Arc<CorpusSourceSinkRegistry>,
    environment: Option<Environment>,
    use_compiler: bool,
    rust_hir: Option<Arc<RustHirMap>>,
) -> Box<dyn SemanticProvider> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    #[cfg(feature = "rust-hir")]
    if use_compiler && ext == "rs" {
        if let Some(hir) = rust_hir {
            return Box::new(RustHirProvider::new(hir));
        }
    }

    if use_compiler
        && matches!(
            ext.as_str(),
            "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs"
        )
    {
        return Box::new(OxcProvider::analyze(source, path, source_sink, environment));
    }

    Box::new(ImportMapProvider::new(
        ImportMap::build_from_tree(&ext, source, tree.root_node()),
        source_sink,
        environment,
    ))
}
