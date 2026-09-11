// SPDX-License-Identifier: MIT
//!
//! A thread-safe registry that maps file extensions and language names to
//! [`LanguageSpec`] implementations.
//!
//! ## Usage
//!
//! ```rust
//! use frensense_lang::registry::LanguageRegistry;
//!
//! let reg = LanguageRegistry::global();
//! let spec = reg.for_extension("ts").expect("TypeScript not registered");
//! // spec is &dyn LanguageSpec — call any trait method
//! ```
//!
//! ## Adding a new language
//!
//! 1. Create a new file in `src/providers/` implementing `LanguageSpec`.
//! 2. Call `registry.register(Arc::new(YourProvider))` inside
//!    `LanguageRegistry::build_default()`.
//! 3. Done.  Every engine subsystem picks it up automatically.

use std::sync::{Arc, OnceLock};

use rustc_hash::FxHashMap;

use crate::spec::LanguageSpec;

// ── Registry ──────────────────────────────────────────────────────────────────

/// Thread-safe registry of all known [`LanguageSpec`] implementations.
pub struct LanguageRegistry {
    by_ext: FxHashMap<&'static str, Arc<dyn LanguageSpec>>,
    by_name: FxHashMap<&'static str, Arc<dyn LanguageSpec>>,
}

impl LanguageRegistry {
    // ── Global singleton ──────────────────────────────────────────────────

    /// Returns the process-wide default registry, constructed once on first call.
    ///
    /// The default registry includes every language enabled via Cargo features.
    /// See [`build_default`](Self::build_default).
    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<LanguageRegistry> = OnceLock::new();
        INSTANCE.get_or_init(Self::build_default)
    }

    // ── Construction ─────────────────────────────────────────────────────

    /// Build the default registry from all feature-gated providers.
    fn build_default() -> Self {
        let mut reg = Self {
            by_ext: FxHashMap::default(),
            by_name: FxHashMap::default(),
        };

        #[cfg(feature = "typescript")]
        reg.register(Arc::new(crate::providers::javascript::TypeScriptSpec));

        #[cfg(feature = "javascript")]
        reg.register(Arc::new(crate::providers::javascript::JavaScriptSpec));

        #[cfg(feature = "go")]
        reg.register(Arc::new(crate::providers::go::GoSpec));

        #[cfg(feature = "python")]
        reg.register(Arc::new(crate::providers::python::PythonSpec));

        #[cfg(feature = "rust-grammar")]
        reg.register(Arc::new(crate::providers::rust_lang::RustSpec));

        #[cfg(feature = "c-grammar")]
        reg.register(Arc::new(crate::providers::c_lang::CSpec));

        reg
    }

    /// Register a [`LanguageSpec`] for all extensions it declares.
    ///
    /// Call this before [`global`](Self::global) is first accessed if you need
    /// to add custom providers (e.g. in tests or downstream crates).
    pub fn register(&mut self, spec: Arc<dyn LanguageSpec>) {
        for &ext in spec.extensions() {
            self.by_ext.insert(ext, Arc::clone(&spec));
        }
        self.by_name.insert(spec.name(), spec);
    }

    // ── Lookups ───────────────────────────────────────────────────────────

    /// Look up the spec for a file extension (lowercase, no leading dot).
    ///
    /// Returns `None` when the extension is unknown — the engine should skip
    /// or fall back gracefully.
    #[must_use]
    pub fn for_extension(&self, ext: &str) -> Option<&dyn LanguageSpec> {
        self.by_ext.get(ext).map(Arc::as_ref)
    }

    /// Look up the spec by the canonical language name.
    #[must_use]
    pub fn for_name(&self, name: &str) -> Option<&dyn LanguageSpec> {
        self.by_name.get(name).map(Arc::as_ref)
    }

    /// Look up the spec for a file path, extracting the extension automatically.
    #[must_use]
    pub fn for_path(&self, path: &std::path::Path) -> Option<&dyn LanguageSpec> {
        let ext = path.extension()?.to_str()?.to_lowercase();
        self.for_extension(ext.as_str())
    }

    /// All registered language names.
    pub fn language_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.by_name.keys().copied()
    }
}

// ── Convenience free functions ─────────────────────────────────────────────────

/// Convenience: `spec_for_ext("ts")` → `Some(&dyn LanguageSpec)`.
#[inline]
pub fn spec_for_ext(ext: &str) -> Option<&'static dyn LanguageSpec> {
    LanguageRegistry::global().for_extension(ext)
}

/// Convenience: `spec_for_path(Path::new("src/main.rs"))`.
#[inline]
pub fn spec_for_path(path: &std::path::Path) -> Option<&'static dyn LanguageSpec> {
    LanguageRegistry::global().for_path(path)
}
