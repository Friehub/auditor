// SPDX-License-Identifier: MIT

use rustc_hash::{FxHashMap, FxHashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkContext {
    Sql,
    Url,
    FilePath,
}

#[derive(Debug, Clone, Default)]
pub struct SanitizerRegistry {
    // Full sanitizer: return value is clean regardless of input
    pub full_sanitizers: FxHashSet<String>,
    // Partial sanitizer: clean for a specific context only
    // (e.g., encodeURIComponent is safe for URL but not SQL)
    pub context_sanitizers: FxHashMap<String, SinkContext>,
}

impl SanitizerRegistry {
    pub fn default_ts() -> Self {
        let mut r = Self::default();
        // Numeric coercion — clears all injection risk
        r.full_sanitizers.extend([
            "parseInt".into(),
            "parseFloat".into(),
            "Number".into(),
            "BigInt".into(),
            "Math.round".into(),
            "Math.floor".into(),
            "Math.ceil".into(),
            "Math.abs".into(),
            "Boolean".into(),
        ]);
        // Parameterized binding — clears SQL injection specifically
        r.context_sanitizers.insert("bind".into(), SinkContext::Sql);
        r.context_sanitizers
            .insert("$1_placeholder".into(), SinkContext::Sql);
        r.context_sanitizers
            .insert("db.prepare".into(), SinkContext::Sql);
        r.context_sanitizers
            .insert("sqlQuery.$1".into(), SinkContext::Sql);
        // HTML escaping
        r.full_sanitizers.extend([
            "he.escape".into(),
            "escapeHtml".into(),
            "sanitizeHtml".into(),
            "DOMPurify.sanitize".into(),
            "validator.escape".into(),
            "xss".into(),
        ]);
        // URL encoding — clears SSRF/redirect but not SQL
        r.context_sanitizers
            .insert("encodeURIComponent".into(), SinkContext::Url);
        r.context_sanitizers
            .insert("encodeURI".into(), SinkContext::Url);
        r.context_sanitizers.insert("URL".into(), SinkContext::Url);
        r.context_sanitizers
            .insert("new URL".into(), SinkContext::Url);
        r.context_sanitizers
            .insert("url.pathname".into(), SinkContext::Url);
        // UUID generation — replaces user input with safe value
        r.full_sanitizers
            .extend(["crypto.randomUUID".into(), "uuidv4".into(), "nanoid".into()]);
        // Buffer clearing — only clears binary encoding confusion
        r.full_sanitizers.extend(["Buffer.from".into()]);
        // Path safety (partial — path.normalize does NOT sanitize traversal)
        r.context_sanitizers
            .insert("path.basename".into(), SinkContext::FilePath);
        r
    }

    pub fn default_rust() -> Self {
        let mut r = Self::default();
        r.full_sanitizers.extend([
            "parse::<u64>".into(),
            "parse::<i64>".into(),
            "parse::<usize>".into(),
            "parse::<f64>".into(),
            "to_string".into(),
            "percent_encode".into(),
            "htmlescape::encode_minimal".into(),
            "uuid::Uuid::new_v4".into(),
        ]);
        r.context_sanitizers
            .insert("sqlx::query!".into(), SinkContext::Sql);
        r.context_sanitizers
            .insert("sqlx::query().bind".into(), SinkContext::Sql);
        r.context_sanitizers.insert("bind".into(), SinkContext::Sql);
        r
    }

    pub fn default_combined() -> Self {
        let mut r = Self::default_ts();
        let rust = Self::default_rust();
        r.full_sanitizers.extend(rust.full_sanitizers);
        r.context_sanitizers.extend(rust.context_sanitizers);
        r
    }

    pub fn load_from_spec(&mut self, spec: &dyn frensense_lang::LanguageSpec) {
        // Reclassify every existing entry through the spec instead of probing
        // a hardcoded candidate list.  This ensures the registry stays in sync
        // with the spec's full sanitizer catalogue.

        let full_names: Vec<String> = self.full_sanitizers.iter().cloned().collect();
        let ctx_names: Vec<String> = self.context_sanitizers.keys().cloned().collect();

        // Full sanitizers → reclassify
        for name in &full_names {
            self.full_sanitizers.remove(name);
            if let Some(kind) = spec.classify_sanitizer(name) {
                match kind {
                    frensense_lang::SanitizerKind::Full => {
                        self.full_sanitizers.insert(name.clone());
                    }
                    frensense_lang::SanitizerKind::HtmlEscape
                    | frensense_lang::SanitizerKind::UrlEncode => {
                        self.context_sanitizers
                            .insert(name.clone(), SinkContext::Url);
                    }
                    frensense_lang::SanitizerKind::SqlParameterize => {
                        self.context_sanitizers
                            .insert(name.clone(), SinkContext::Sql);
                    }
                    frensense_lang::SanitizerKind::PathNormalize => {
                        self.context_sanitizers
                            .insert(name.clone(), SinkContext::FilePath);
                    }
                }
            }
        }

        // Context sanitizers → reclassify
        for name in &ctx_names {
            self.context_sanitizers.remove(name);
            if let Some(kind) = spec.classify_sanitizer(name) {
                match kind {
                    frensense_lang::SanitizerKind::Full => {
                        self.full_sanitizers.insert(name.clone());
                    }
                    frensense_lang::SanitizerKind::HtmlEscape
                    | frensense_lang::SanitizerKind::UrlEncode => {
                        self.context_sanitizers
                            .insert(name.clone(), SinkContext::Url);
                    }
                    frensense_lang::SanitizerKind::SqlParameterize => {
                        self.context_sanitizers
                            .insert(name.clone(), SinkContext::Sql);
                    }
                    frensense_lang::SanitizerKind::PathNormalize => {
                        self.context_sanitizers
                            .insert(name.clone(), SinkContext::FilePath);
                    }
                }
            }
        }
    }

    pub fn is_full_sanitizer(&self, name: &str) -> bool {
        self.full_sanitizers.contains(name)
    }

    /// Check if `name` is a full sanitizer, also consulting the spec when
    /// available.  This allows the engine to recognise sanitizers that are not
    /// in the hardcoded defaults but are declared by the language spec.
    pub fn is_full_sanitizer_with_spec(
        &self,
        name: &str,
        spec: Option<&dyn frensense_lang::LanguageSpec>,
    ) -> bool {
        if self.full_sanitizers.contains(name) {
            return true;
        }
        if let Some(s) = spec {
            if let Some(kind) = s.classify_sanitizer(name) {
                return matches!(kind, frensense_lang::SanitizerKind::Full);
            }
        }
        false
    }
}
