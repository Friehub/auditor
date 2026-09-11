use std::fs;
use std::path::Path;

/// Returns true if a file name represents any negative variant:
/// `_negative.ts`, `_negative2.ts`, `_negative3.ts`, etc.
/// Recursively collect all corpus files from a directory tree.
pub(crate) fn collect_corpus_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return result;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            result.extend(collect_corpus_files(&path));
        } else if path.is_file() {
            result.push(path);
        }
    }
    result
}

pub(crate) fn is_negative_file(file_name: &str) -> bool {
    // Strip the extension first, then check suffix
    let stem = file_name.rsplitn(2, '.').last().unwrap_or(file_name);
    if stem.ends_with("_negative") {
        return true;
    }
    // Match _negative2, _negative3, ... _negative9
    if let Some(prefix) = stem.strip_suffix(|c: char| c.is_ascii_digit()) {
        if prefix.ends_with("_negative") {
            return true;
        }
    }
    false
}

pub(crate) fn extract_pattern_name(file_name: &str) -> String {
    let without_ext = file_name.rsplitn(2, '.').last().unwrap_or(file_name);

    // Positive files: just strip _positive suffix (single occurrence)
    if let Some(stripped) = without_ext.strip_suffix("_positive") {
        return stripped.to_string();
    }

    // Negative files: strip _negative, _negative2 ... _negative9 (single occurrence)
    if let Some(stripped) = without_ext.strip_suffix("_negative") {
        return stripped.to_string();
    }
    if let Some(digits) = without_ext.strip_suffix(|c: char| c.is_ascii_digit()) {
        if let Some(stripped) = digits.strip_suffix("_negative") {
            return stripped.to_string();
        }
    }

    without_ext.to_string()
}
