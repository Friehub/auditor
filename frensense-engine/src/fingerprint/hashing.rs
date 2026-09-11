// SPDX-License-Identifier: MIT

use rustc_hash::{FxHashSet, FxHasher};
use std::hash::{Hash, Hasher};

/// Normalize a token to its canonical form so structurally equivalent constructs
/// hash identically. Applied before n-gram computation.
pub(super) fn normalize_token(tok: &str) -> &str {
    match tok {
        "while" | "for" | "loop" | "do" => "loop",
        "if" | "switch" | "match" => "branch",
        "catch" | "except" | "rescue" | "recover" => "catch",
        "async" | "await" | "yield" | "suspend" => "async_op",
        "return" | "break" | "continue" | "throw" | "raise" => "exit",
        other => other,
    }
}

/// Position-weighted n-gram hashing.
/// Combines position with token hash so `return` at line 5 differs from `return` at line 50.
pub(super) fn token_ngrams_positional(tokens: &[String], window_size: usize) -> Vec<u64> {
    if tokens.len() < window_size {
        return Vec::new();
    }
    let mut hashes = FxHashSet::default();
    let total = tokens.len();
    for i in 0..=(total.saturating_sub(window_size)) {
        let mut fx_hasher = FxHasher::default();
        tokens[i..i + window_size].hash(&mut fx_hasher);
        let token_hash = fx_hasher.finish();
        let position = if total > 1 {
            i as f32 / (total - 1) as f32
        } else {
            0.0
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let position_bits = (position * 1024.0) as u64;
        let mut final_hasher = FxHasher::default();
        token_hash.hash(&mut final_hasher);
        position_bits.hash(&mut final_hasher);
        hashes.insert(final_hasher.finish());
    }
    let mut vec: Vec<u64> = hashes.into_iter().collect();
    vec.sort_unstable();
    vec
}

pub(super) fn token_ngrams(tokens: &[String], window_size: usize) -> FxHashSet<u64> {
    if tokens.len() < window_size {
        return FxHashSet::default();
    }
    let mut hashes = FxHashSet::default();
    for i in 0..=(tokens.len().saturating_sub(window_size)) {
        let mut fx_hasher = FxHasher::default();
        tokens[i..i + window_size].hash(&mut fx_hasher);
        hashes.insert(fx_hasher.finish());
    }
    hashes
}

pub(super) fn token_ngrams_sorted(tokens: &[String], window_size: usize) -> Vec<u64> {
    let mut vec: Vec<u64> = token_ngrams(tokens, window_size).into_iter().collect();
    vec.sort_unstable();
    vec
}

pub(super) fn split_name_segments(name: &str) -> Vec<String> {
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    for ch in name.chars() {
        if ch.is_uppercase() && !current.is_empty() {
            segments.push(std::mem::take(&mut current));
        }
        if ch != '_' {
            current.push(ch);
        } else if !current.is_empty() {
            segments.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}
