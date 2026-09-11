// SPDX-License-Identifier: MIT

use crate::FrensenseError;
use crate::Result;
use std::path::Path;
use tree_sitter::Language;

/// Maps file extensions to tree-sitter language names.
/// Kept for backwards compatibility for non-spec languages like HTML/YAML.
const LANGUAGE_EXTENSIONS: &[(&[&str], &[&str])] = &[
    (&["rust"], &["rs"]),
    (&["typescript", "ts"], &["ts", "tsx"]),
    (&["javascript", "js"], &["js", "jsx"]),
    (&["python", "py"], &["py", "pyi"]),
    (&["go"], &["go"]),
    (&["c"], &["c", "h"]),
    (&["yaml", "yml"], &["yml", "yaml"]),
    (&["html"], &["html", "htm"]),
];

/// Maps file extension to human-readable language name.
pub fn ext_to_language(ext: &str) -> &'static str {
    if let Some(spec) = frensense_lang::spec_for_ext(ext) {
        return spec.name();
    }
    match ext {
        "yml" | "yaml" => "yaml",
        "html" | "htm" => "html",
        _ => "unknown",
    }
}

/// Check whether a file has a supported extension.
pub fn is_supported(path: &Path) -> bool {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if frensense_lang::spec_for_ext(ext).is_some() {
        return true;
    }
    matches!(ext, "yml" | "yaml" | "json" | "html" | "htm")
}

/// Look up file extensions for a language name (e.g. `rust` → `["rs"]`).
pub fn extensions_for(name: &str) -> Option<&'static [&'static str]> {
    let lower = name.to_lowercase();

    // First try the spec registry if it matches exactly
    if let Some(spec) = frensense_lang::registry::LanguageRegistry::global().for_name(&lower) {
        return Some(spec.extensions());
    }

    // Fallback to legacy map
    LANGUAGE_EXTENSIONS
        .iter()
        .find(|(names, _)| names.contains(&lower.as_str()))
        .map(|(_, exts)| *exts)
}

/// Check whether a file extension matches one of the given allowed extensions.
pub fn ext_matches(ext: &str, allowed: &[&str]) -> bool {
    allowed.contains(&ext)
}

/// Tree-sitter symbol query for a file extension.
pub fn symbol_query_for_ext(ext: &str) -> Option<&'static str> {
    if let Some(spec) = frensense_lang::spec_for_ext(ext) {
        return spec.symbol_query();
    }
    match ext {
        "html" | "htm" => Some(
            r"
            (element (tag_name) @name)
            (script_element (tag_name) @name)
            (style_element (tag_name) @name)
        ",
        ),
        _ => None,
    }
}

/// Tree-sitter call query for a file extension.
pub fn call_query_for_ext(ext: &str) -> Option<&'static str> {
    if let Some(spec) = frensense_lang::spec_for_ext(ext) {
        return spec.call_query();
    }
    None
}

pub struct ParserRegistry;

impl ParserRegistry {
    /// Returns the tree-sitter language for a given file path.
    pub fn get_language(path: &Path) -> Result<Language> {
        let ext = path.extension().and_then(|s| s.to_str()).ok_or_else(|| {
            FrensenseError::Config(format!("File has no extension: {}", path.display()))
        })?;

        if let Some(spec) = frensense_lang::spec_for_ext(ext) {
            return Ok(spec.tree_sitter_language());
        }

        match ext {
            #[cfg(feature = "html")]
            "html" | "htm" => Ok(tree_sitter_html::LANGUAGE.into()),
            "yml" | "yaml" => Err(FrensenseError::Config(format!(
                "YAML tree-sitter parsing not available in the engine (use consumer crate). Extension: {ext}"
            ))),
            _ => Err(FrensenseError::Config(format!(
                "Unsupported file extension or feature not enabled: {ext}"
            ))),
        }
    }

    /// Returns the tree-sitter language for a language name string.
    pub fn get_language_by_name(name: &str) -> Result<Language> {
        let lower = name.to_lowercase();
        if let Some(spec) = frensense_lang::registry::LanguageRegistry::global().for_name(&lower) {
            return Ok(spec.tree_sitter_language());
        }

        match lower.as_str() {
            "yaml" | "yml" => Self::get_language(Path::new("x.yaml")),
            "html" => Self::get_language(Path::new("x.html")),
            _ => Err(FrensenseError::Config(format!(
                "Unsupported language: {name}"
            ))),
        }
    }

    pub fn get_symbol_query_by_ext(&self, ext: &str) -> Option<&'static str> {
        symbol_query_for_ext(ext)
    }

    pub fn get_call_query_by_ext(&self, ext: &str) -> Option<&'static str> {
        call_query_for_ext(ext)
    }

    pub fn is_supported(path: &Path) -> bool {
        crate::parser::is_supported(path)
    }

    pub fn extensions_for(name: &str) -> Option<&'static [&'static str]> {
        crate::parser::extensions_for(name)
    }

    pub fn get_symbol_query(path: &Path) -> Option<&'static str> {
        let ext = path.extension().and_then(|s| s.to_str())?;
        symbol_query_for_ext(ext)
    }

    pub fn get_call_query(path: &Path) -> Option<&'static str> {
        let ext = path.extension().and_then(|s| s.to_str())?;
        call_query_for_ext(ext)
    }

    pub fn ext_matches(ext: &str, allowed: &[&str]) -> bool {
        crate::parser::ext_matches(ext, allowed)
    }
}
