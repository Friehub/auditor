#![allow(unused)]
#![allow(clippy::all)]
#![allow(dead_code, unreachable_patterns, unreachable_code)]
// SPDX-License-Identifier: MIT
//! Builds the corpus fingerprint bundle (frensense-corpus.frc).
//!
//! Usage: cargo run --bin build-corpus-bundle [--incremental]
//!
//! Reads corpus/targets/, extracts fingerprints, writes frensense-corpus.frc.
//! With --incremental, only reprocesses changed files using a manifest.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").map_or_else(|_| env::current_dir().unwrap(), PathBuf::from);

    // CARGO_MANIFEST_DIR will point to frensense-bundler/. We need the workspace root.
    let workspace_root = manifest_dir.parent().unwrap();
    let corpus_dir = workspace_root.join("corpus").join("targets");
    let output_path = workspace_root.join("frensense-corpus.frc");

    // nosemgrep: rust.lang.security.args.args
    let incremental = env::args().any(|a| a == "--incremental");

    if incremental {
        eprintln!(
            "Building corpus bundle (incremental) from {}...",
            corpus_dir.display()
        );
    } else {
        eprintln!("Building corpus bundle from {}...", corpus_dir.display());
    }

    let bytes = if incremental {
        match frensense_bundler::builder::build_bundle_incremental(&corpus_dir) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error building bundle: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match frensense_bundler::builder::build_bundle(&corpus_dir) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Error building bundle: {e}");
                std::process::exit(1);
            }
        }
    };

    let loaded = match frensense_engine::corpus::bundle::load_bundle(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error verifying bundle: {e}");
            std::process::exit(1);
        }
    };

    let total_fingerprints: usize = loaded
        .patterns
        .iter()
        .map(|p| p.positives.len() + p.negatives.len())
        .sum();

    std::fs::write(&output_path, &bytes).unwrap_or_else(|e| {
        eprintln!("Error writing bundle: {e}");
        std::process::exit(1);
    });

    eprintln!(
        "Bundle written to {} ({} bytes, {} patterns, {} fingerprints)",
        output_path.display(),
        bytes.len(),
        loaded.patterns.len(),
        total_fingerprints,
    );
}
