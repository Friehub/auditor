// SPDX-License-Identifier: MIT

//! Fingerprint module — split across focused sub-modules.
//!
//! Public API is identical to the old flat `fingerprint.rs`.

mod ast_walkers;
mod extraction;
mod hashing;
mod types;

pub use extraction::{extract_fingerprints, extract_fingerprints_with_nodes};
pub use types::{FunctionFingerprint, apply_idf_weights, compute_idf_weights};
