// SPDX-License-Identifier: MIT

//! Implementation 3 — [`RustHirProvider`]: type-checked Rust facts via the
//! rust-analyzer HIR (`ra_ap_*`), opt-in with the `rust-hir` feature /
//! `--use-compiler`.
//!
//! The tree-sitter heuristics guess at Rust semantics from names and syntax.
//! The HIR replaces those guesses with type-checked facts:
//!
//! - `async fn handler(body: Json<CreateUser>) -> impl IntoResponse` — the
//!   return type's `impl Trait` bounds name `IntoResponse`, so this is an HTTP
//!   handler because the *trait says so*, not because of a `req` parameter
//!   name or a `res.send()` call. This is the "one fact" the HIR gives us.
//! - `Json<CreateUser>` — the parameter's type resolves to `axum::extract::Json`,
//!   so the parameter is user input even when its name is `body`.
//! - `mutex.lock().unwrap()` — `MutexGuard` implements `Drop`; the RAII
//!   exemption in [`frensense_engine::temporal`] is a *type* fact, not a `let`-binding
//!   syntax guess. (Expression-level; currently the module exposes the
//!   function-level facts that feed into it.)
//!
//! Cost: building the HIR runs `cargo metadata` and type-checks the workspace
//! on demand. That is why this provider is opt-in (non-default feature, the
//! `--use-compiler` flag) and why it remains optional until the corpus engine
//! needs richer type-level facts.

use std::path::Path;
use std::sync::Arc;

use ra_ap_base_db::{CrateOrigin, FileChange, SourceRoot};
use ra_ap_hir::{Adt, Crate, DisplayTarget, HirDisplay, ModuleDef};
use ra_ap_ide_db::RootDatabase;
use ra_ap_paths::{AbsPath, AbsPathBuf};
use ra_ap_project_model::{CargoConfig, ProjectManifest, ProjectWorkspace, RustLibSource};
use ra_ap_vfs::{FileId, VfsPath, file_set::FileSet};
use rustc_hash::FxHashMap;

use frensense_engine::corpus::source_sink::SinkCategory;
use frensense_engine::data_flow::TaintOrigin;
use frensense_engine::fingerprint::FunctionFingerprint;
use frensense_engine::function_role::FunctionRole;
use frensense_engine::semantic::{
    FunctionHirFact, HirTypeMap, SemanticProvider, TypeContext, base_type_name,
};

/// Canonical-path prefixes that mark a type as HTTP user input. The HIR has
/// already resolved the base name to a real type; these only decide whether
/// that type is a request extractor. Kept to real framework paths (plus the
/// generic `::extract::` module convention they all share).
const HTTP_EXTRACTOR_PREFIXES: &[&str] = &[
    "axum::extract::",
    "axum::Json",
    "axum::Form",
    "axum::Query",
    "actix_web::web::Json",
    "actix_web::web::Form",
    "actix_web::web::Query",
    "actix_web::http::",
    "rocket::serde::json::Json",
];

/// Canonical-path prefixes whose types are dangerous by construction: any
/// value of such a type is a sink in that category regardless of the method
/// name. The Rust analogue of [`frensense_engine::semantic`]'s JS `PACKAGE_SINK_CATEGORIES`;
/// this is what takes over the Rust sink names the `--use-compiler` path
/// removes from [`frensense_engine::corpus::source_sink::ALWAYS_REGISTER_SINKS`].
const RUST_SINK_TYPES: &[(&str, SinkCategory)] = &[
    ("sqlx::", SinkCategory::SqlInjection),
    ("tokio_postgres::", SinkCategory::SqlInjection),
    ("postgres::", SinkCategory::SqlInjection),
    ("rusqlite::", SinkCategory::SqlInjection),
    ("mysql::", SinkCategory::SqlInjection),
    ("redis::", SinkCategory::NoSqlInjection),
    ("mongodb::", SinkCategory::NoSqlInjection),
    ("std::process::Command", SinkCategory::CommandInjection),
    ("std::fs::", SinkCategory::PathTraversal),
    ("std::net::", SinkCategory::Ssrf),
    ("reqwest::", SinkCategory::Ssrf),
];

/// Build the type-checked [`HirTypeMap`] for a cargo workspace.
///
/// `manifest_path` points at the root `Cargo.toml`. This runs `cargo metadata`
/// (so it needs a buildable workspace) and then type-checks on demand, which
/// is why the `RustHirProvider` is opt-in.
///
/// The returned map is fully owned — the HIR database is dropped before this
/// returns — so it can be shared across threads like
/// [`frensense_engine::semantic::OxcSymbolTable`].
///
/// Returns an error string on failure (no manifest, cargo metadata failure).
pub fn build_hir_type_map(manifest_path: &Path) -> Result<HirTypeMap, String> {
    let utf8 = camino_utf8(manifest_path)?;
    let manifest =
        ProjectManifest::discover_single(AbsPath::assert(utf8)).map_err(|e| format!("{e}"))?;
    // Load the toolchain sysroot so `core`, `std`, `alloc` and their languages
    // items (`Future`, `Sized`) resolve. `CargoConfig::default()` disables the
    // sysroot, which would leave every std/framework type opaque.
    let config = CargoConfig {
        sysroot: Some(RustLibSource::Discover),
        ..CargoConfig::default()
    };
    let workspace =
        ProjectWorkspace::load(manifest, &config, &|_| {}).map_err(|e| format!("{e}"))?;

    // Assign a stable FileId to every source file the crate graph touches, and
    // remember the path for each id so facts can be keyed by file path later.
    let mut path_to_id: FxHashMap<AbsPathBuf, FileId> = FxHashMap::default();
    let mut id_to_path: FxHashMap<FileId, AbsPathBuf> = FxHashMap::default();
    let mut next_id: u32 = 1;
    {
        let mut loader = |path: &AbsPath| -> Option<FileId> {
            let abs = path.to_path_buf();
            let id = *path_to_id.entry(abs.clone()).or_insert_with(|| {
                let id = FileId::from_raw(next_id);
                next_id += 1;
                id
            });
            id_to_path.insert(id, abs);
            Some(id)
        };
        let (crate_graph, _proc_macro_paths) =
            workspace.to_crate_graph(&mut loader, &std::collections::HashMap::default());

        // The crate graph only gives the loader crate *root* files. Submodule
        // files (`mod foo;`) are resolved lazily through the source-root file
        // set, so walk every crate's source directory to discover them too —
        // otherwise `use axum::Json` where `Json` lives in `axum/src/extract.rs`
        // would resolve to an unknown type.
        for crate_id in crate_graph.iter() {
            let root_file = crate_graph[crate_id].basic.root_file_id;
            if let Some(path) = id_to_path.get(&root_file).cloned() {
                collect_source_files(&path, &mut path_to_id, &mut id_to_path, &mut next_id);
            }
        }

        // Load every discovered source file into the database and wire the
        // source root so relative `mod` resolution works.
        let mut file_set = FileSet::default();
        let mut change = FileChange::default();
        for (path, id) in &path_to_id {
            file_set.insert(*id, VfsPath::from(path.clone()));
            let text = std::fs::read_to_string(path).unwrap_or_default();
            change.change_file(*id, Some(text));
        }
        change.set_roots(vec![SourceRoot::new_local(file_set)]);
        change.set_crate_graph(crate_graph);

        let mut db = RootDatabase::new(None);
        change.apply(&mut db);
        // The ra_ap type checker reads its database from a thread-local slot;
        // HIR queries called outside of a salsa query must attach it explicitly.
        Ok(ra_ap_hir::attach_db_allow_change(&db, || {
            collect_hir_type_map(&db, &id_to_path)
        }))
    }
}

/// Recursively discover every `*.rs` file under the directory containing
/// `crate_root`, allocating a `FileId` for each. Deduplicated against
/// `path_to_id`, so shared sources (registry, sysroot) are visited once.
fn collect_source_files(
    crate_root: &AbsPathBuf,
    path_to_id: &mut FxHashMap<AbsPathBuf, FileId>,
    id_to_path: &mut FxHashMap<FileId, AbsPathBuf>,
    next_id: &mut u32,
) {
    let Some(start) = crate_root.parent() else {
        return;
    };
    let mut stack = vec![start.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if !entry
                    .file_name()
                    .to_string_lossy()
                    .eq_ignore_ascii_case("target")
                {
                    let Ok(utf8) = ra_ap_paths::Utf8PathBuf::from_path_buf(path) else {
                        continue;
                    };
                    stack.push(AbsPathBuf::assert(utf8));
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let Ok(utf8) = ra_ap_paths::Utf8PathBuf::from_path_buf(path) else {
                    continue;
                };
                let abs = AbsPathBuf::assert(utf8);
                let id = *path_to_id.entry(abs.clone()).or_insert_with(|| {
                    let id = FileId::from_raw(*next_id);
                    *next_id += 1;
                    id
                });
                id_to_path.insert(id, abs);
            }
        }
    }
}

/// Convert a std `Path` to a `Utf8Path`, mapping non-UTF-8 paths to an error.
fn camino_utf8(path: &Path) -> Result<&ra_ap_paths::Utf8Path, String> {
    ra_ap_paths::Utf8Path::from_path(path)
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

/// Canonical path of an ADT including its crate name, e.g.
/// `axum::extract::Json`. `ModuleDef::canonical_path` omits the crate root
/// (the root module is nameless), so the crate display name is prepended here.
fn canonical_adt_path(db: &RootDatabase, adt: Adt) -> Option<String> {
    let module = ModuleDef::from(adt).module(db)?;
    let mut segments: Vec<String> = Vec::new();
    if let Some(crate_name) = module.krate(db).display_name(db) {
        segments.push(crate_name.to_string());
    }
    segments.extend(module.path_segments(db).map(|n| n.as_str().to_owned()));
    segments.push(adt.name(db).as_str().to_owned());
    Some(segments.join("::"))
}

/// Walk every local crate's HIR and collect the type-checked facts into an
/// owned [`HirTypeMap`].
fn collect_hir_type_map(
    db: &RootDatabase,
    id_to_path: &FxHashMap<FileId, AbsPathBuf>,
) -> HirTypeMap {
    let mut map = HirTypeMap::default();

    for krate in Crate::all(db) {
        if !matches!(krate.origin(db), CrateOrigin::Local { .. }) {
            continue;
        }
        let display_target = DisplayTarget::from_crate(db, krate.base());

        for module in krate.modules(db) {
            // The module's defining file. Inline modules (`mod foo {}`) report
            // the enclosing file, which is what we want.
            let Some(file_id) = module
                .definition_source(db)
                .file_id
                .file_id()
                .map(|e| e.file_id(db))
            else {
                continue;
            };
            let Some(path) = id_to_path.get(&file_id) else {
                continue;
            };
            let file_path = path.as_str().to_owned();

            for def in module.declarations(db) {
                let ModuleDef::Function(func) = def else {
                    continue;
                };

                let name = func.name(db).as_str().to_owned();
                let is_async = func.is_async(db);
                // The type-checked return type. For `async fn` this is the
                // `Future`'s `Output` — otherwise `ret_type` yields the opaque
                // `impl Future<...>` and the handler's own trait is hidden.
                let ret_type = if is_async {
                    func.async_ret_type(db).unwrap_or_else(|| func.ret_type(db))
                } else {
                    func.ret_type(db)
                };

                // The single handler fact: `-> impl IntoResponse` names its
                // trait in the type-checked return type.
                let return_trait_bounds: Vec<String> = ret_type
                    .as_impl_traits(db)
                    .map(|it| {
                        it.filter(|trait_| trait_.name(db).as_str() != "Sized")
                            .map(|trait_| trait_.name(db).as_str().to_owned())
                            .collect()
                    })
                    .unwrap_or_default();

                let mut params = Vec::new();
                for param in func.params_without_self(db) {
                    let param_name = param.name(db).map(|n| n.as_str().to_owned());
                    let rendered = param.ty().display(db, display_target).to_string();

                    // Record the base name → canonical path, e.g. "Json" →
                    // "axum::extract::Json", for later parameter classification.
                    if let Some(adt) = param.ty().strip_references().as_adt()
                        && let Some(canonical) = canonical_adt_path(db, adt)
                    {
                        let base = canonical.rsplit("::").next().unwrap_or(&canonical);
                        map.type_paths
                            .entry(base.to_owned())
                            .or_insert_with(|| canonical);
                    }

                    params.push((param_name, rendered));
                }

                map.functions.insert(
                    (file_path.clone(), name),
                    FunctionHirFact {
                        is_async,
                        return_trait_bounds,
                        params,
                    },
                );
            }
        }
    }

    map
}

/// Is a canonical type path an HTTP request extractor / source?
fn is_http_source_type(canonical: &str) -> bool {
    HTTP_EXTRACTOR_PREFIXES
        .iter()
        .any(|prefix| canonical.starts_with(prefix))
}

/// Map a canonical type path to the sink category of anything of that type.
fn rust_sink_category(path: &str) -> Option<SinkCategory> {
    RUST_SINK_TYPES
        .iter()
        .find(|(prefix, _)| path.starts_with(prefix))
        .map(|&(_, category)| category)
}

/// Implementation 3 — answers the semantic questions from the type-checked
/// [`HirTypeMap`]. Shared across files like the other providers; constructed
/// once per project with the result of [`build_hir_type_map`].
#[derive(Debug, Clone)]
pub struct RustHirProvider {
    hir_types: Arc<HirTypeMap>,
}

impl RustHirProvider {
    /// Build a provider over a type-checked workspace.
    #[must_use]
    pub fn new(hir_types: Arc<HirTypeMap>) -> Self {
        Self { hir_types }
    }

    /// Access the type-checked facts.
    #[must_use]
    pub fn hir_types(&self) -> &HirTypeMap {
        &self.hir_types
    }
}

impl SemanticProvider for RustHirProvider {
    fn classify_param(&self, name: &str, type_annotation: Option<&str>) -> Option<TaintOrigin> {
        // Type-confirmed: the annotation's base name resolves to a real type
        // in the HIR, and that type is an HTTP extractor.
        if let Some(annotation) = type_annotation {
            let base = base_type_name(annotation);
            if let Some(canonical) = self.hir_types.resolve_type(base)
                && is_http_source_type(canonical)
            {
                return Some(TaintOrigin::UserInput);
            }
        }
        // Name-based fallback for unannotated parameters.
        frensense_engine::data_flow::classify_param_name_in_context(name, None)
    }

    fn classify_sink(
        &self,
        call_text: &str,
        resolved_module: Option<&str>,
    ) -> Option<SinkCategory> {
        // 1. A canonical receiver type (when the caller knows it) is a sink by
        //    construction: `pool.execute(...)` where `pool: sqlx::PgPool`.
        if let Some(module) = resolved_module
            && let Some(category) = rust_sink_category(module)
        {
            return Some(category);
        }
        // 2. Receiver name resolved through the type map: a local declared
        //    with a dangerous type, e.g. `let client: sqlx::PgPool`.
        if let Some(receiver) = call_text.split('.').next()
            && let Some(canonical) = self.hir_types.resolve_type(receiver)
            && let Some(category) = rust_sink_category(canonical)
        {
            return Some(category);
        }
        None
    }

    fn is_http_handler(&self, fp: &FunctionFingerprint, type_context: &TypeContext) -> bool {
        // Type-confirmed: the fingerprinted function returns `impl
        // IntoResponse` according to the HIR — a single signal is sufficient.
        if let Some(facts) = type_context
            .hir_types
            .and_then(|map| map.function_facts(&fp.file_path, &fp.function_name))
            && facts
                .return_trait_bounds
                .iter()
                .any(|bound| bound == "IntoResponse")
        {
            return true;
        }
        // Fall back to the ≥2 heuristic signals for functions the HIR did not
        // analyse (different target, parse failure, ...).
        frensense_engine::function_role::classify_role_with_imports(fp, None, None)
            == FunctionRole::HttpHandler
    }

    fn file_imports(&self, _package: &str) -> bool {
        false
    }

    fn resolve_name(&self, name: &str) -> Option<String> {
        self.hir_types.type_paths.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Build a tiny two-crate workspace in a tempdir and point the HIR at it.
    /// The `axum` crate stands in for the real one: `axum::extract::Json<T>` is
    /// an extractor and `axum::IntoResponse` is the handler marker trait.
    /// Naming it `axum` (not `web`) lets `HTTP_EXTRACTOR_PREFIXES` match the
    /// canonical paths exactly as it would in production.
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"axum\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("app/src")).unwrap();
        fs::write(
            root.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\naxum = { path = \"../axum\" }\n",
        )
        .unwrap();
        fs::write(
            root.join("app/src/main.rs"),
            "use axum::{IntoResponse, Json};\n\n\
             fn main() {}\n\n\
             async fn handler(body: Json<u64>) -> impl IntoResponse {\n    body.0\n}\n\n\
             fn helper(x: u64) -> u64 { x + 1 }\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("axum/src")).unwrap();
        fs::write(
            root.join("axum/Cargo.toml"),
            "[package]\nname = \"axum\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(
            root.join("axum/src/lib.rs"),
            "pub mod extract;\npub use extract::{IntoResponse, Json};\n",
        )
        .unwrap();
        fs::write(
            root.join("axum/src/extract.rs"),
            "pub struct Json<T>(pub T);\npub trait IntoResponse {}\n",
        )
        .unwrap();
        let main_rs = root.join("app/src/main.rs");
        (dir, main_rs)
    }

    #[test]
    fn builds_hir_type_map_from_workspace() {
        let (_dir, main_rs) = fixture();
        let cargo_toml = main_rs
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("Cargo.toml");

        let map = build_hir_type_map(&cargo_toml).expect("build_hir_type_map");
        let main = main_rs.to_str().unwrap();

        // `handler` is async and its return type is `impl IntoResponse`.
        let handler = map
            .function_facts(main, "handler")
            .expect("handler facts present");
        assert!(handler.is_async);
        assert_eq!(
            handler.return_trait_bounds,
            vec!["IntoResponse".to_string()]
        );

        // The parameter resolves to the extractor type.
        assert_eq!(map.resolve_type("Json"), Some("axum::extract::Json"));
        assert!(
            handler
                .params
                .iter()
                .any(|(name, ty)| name.as_deref() == Some("body") && ty == "Json<u64>")
        );

        // `helper` has no handler facts.
        let helper = map.function_facts(main, "helper").expect("helper facts");
        assert!(!helper.is_async);
        assert!(helper.return_trait_bounds.is_empty());
    }

    #[test]
    fn provider_classifies_from_hir_facts() {
        let (_dir, main_rs) = fixture();
        let cargo_toml = main_rs
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("Cargo.toml");

        let map = Arc::new(build_hir_type_map(&cargo_toml).expect("build_hir_type_map"));
        let provider = RustHirProvider::new(map.clone());

        // Extractor parameter is user input regardless of its name.
        assert_eq!(
            provider.classify_param("body", Some("Json<u64>")),
            Some(TaintOrigin::UserInput),
        );
        // Unresolved types fall back to the name heuristic only.
        assert_eq!(provider.classify_param("x", Some("u64")), None);
        assert_eq!(
            provider.resolve_name("Json"),
            Some("axum::extract::Json".to_string())
        );

        // The handler is recognised from its return type alone.
        let import_map = frensense_engine::import_resolver::ImportMap::new();
        let mut ctx = TypeContext::from_import_map(&import_map);
        ctx.hir_types = Some(&map);
        let handler = fingerprint(main_rs.to_str().unwrap(), "handler");
        assert!(provider.is_http_handler(&handler, &ctx));
        let helper = fingerprint(main_rs.to_str().unwrap(), "helper");
        assert!(!provider.is_http_handler(&helper, &ctx));
    }

    fn fingerprint(file_path: &str, function_name: &str) -> FunctionFingerprint {
        FunctionFingerprint {
            file_path: file_path.to_string(),
            function_name: function_name.to_string(),
            ..FunctionFingerprint {
                file_path: String::new(),
                function_name: String::new(),
                line: 0,
                language: "rust".to_string(),
                ngram_hashes: Vec::new(),
                weighted_ngram_hashes: Default::default(),
                signature_ngrams: Vec::new(),
                param_type_ngrams: Vec::new(),
                name_segments: Vec::new(),
                structural_markers: Vec::new(),
                type_usages: Vec::new(),
                comment_density: 0.0,
                semantic_markers: Vec::new(),
                skeleton: Vec::new(),
                skeleton_hashes: Vec::new(),
                control_flow_hashes: Vec::new(),
                control_flow_sequence: Vec::new(),
                api_calls: Vec::new(),
                api_call_segments: Vec::new(),
                property_accesses: Vec::new(),
                motif_hashes: Vec::new(),
                data_flow_path_hashes: Vec::new(),
                raw_call_names: Vec::new(),
                param_names: Vec::new(),
                tainted_api_calls: Vec::new(),
                config_literal_hashes: Vec::new(),
                argument_call_types: Vec::new(),
                literal_pattern_hashes: Vec::new(),
                has_http_decorator: false,
                is_registered_handler: false,
                export_handler_kind: None,
            }
        }
    }
}
