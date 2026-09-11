#![allow(unused)]
#![allow(clippy::all)]

#[cfg(feature = "oxc")]
pub mod oxc_provider;

#[cfg(feature = "rust-hir")]
pub mod rust_hir_provider;
