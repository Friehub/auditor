#![allow(unused)]
#![allow(clippy::all)]
#![allow(dead_code, unreachable_patterns, unreachable_code)]
// SPDX-License-Identifier: MIT
#![allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cast_precision_loss
)]

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use thiserror::Error;
use tree_sitter::Node;

pub const FRENSENSE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod cli;
pub mod engine;
pub mod mcp;
pub mod parser;
pub mod patcher;
pub mod reporter;
pub mod semantics;
#[cfg(feature = "temporal")]
pub mod temporal;

pub use crate::engine::Engine;
#[cfg(feature = "fingerprinting")]
pub use crate::engine::FunctionFingerprint;
pub use crate::engine::auditor::{FrensenseAuditor, ScanResult};

use crate::semantics::SymbolRegistry;

use frensense_engine::pattern::evidence::MatchEvidence;
pub use frensense_engine::{FileId, ScopeId};

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl Severity {
    #[must_use]
    pub fn meets_threshold(&self, threshold: Severity) -> bool {
        match (self, threshold) {
            (Severity::Critical, _)
            | (Severity::Info, Severity::Info)
            | (Severity::Warning, Severity::Warning | Severity::Info) => true,
            (Severity::Warning, Severity::Critical) | (Severity::Info, _) => false,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrensenseEnvironment {
    Production,
    Staging,
    Development,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Precision {
    VeryHigh,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    Default,
    Extended,
    All,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuleMetadata {
    pub id: Cow<'static, str>,
    pub name: Cow<'static, str>,
    pub severity: Severity,
    pub observation: Cow<'static, str>,
    pub impact: Cow<'static, str>,
    pub improvement: Cow<'static, str>,
    pub tags: Vec<Cow<'static, str>>,
    #[serde(alias = "domain")]
    pub category: Cow<'static, str>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default = "default_precision")]
    pub precision: Precision,
    pub expected_context: Option<frensense_engine::context::FileContext>,
}

const fn default_confidence() -> f64 {
    0.55
}

const fn default_precision() -> Precision {
    Precision::Low
}

impl RuleMetadata {
    #[must_use]
    pub fn meets_suite(&self, suite: Suite) -> bool {
        match suite {
            Suite::Default => self.precision == Precision::VeryHigh,
            Suite::Extended => matches!(self.precision, Precision::VeryHigh | Precision::High),
            Suite::All => true,
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
#[must_use]
pub struct Advisory {
    pub rule_id: String,
    pub file_id: FileId,
    pub file_path: String,
    pub severity: Severity,
    pub confidence: f64,
    pub observation: String,
    pub impact: String,
    pub improvement: String,
    pub line: u32,
    pub column: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    pub original_content: String,
    /// The suggested replacement code, if any.
    pub proposed_replacement: Option<String>,
    /// The suggested import statement to inject, if any.
    pub proposed_import: Option<String>,
    pub enclosing_symbol: Option<String>,
    pub fingerprint: String,
    pub auto_fixable: bool,
    pub requires_human: bool,
    pub tags: Vec<String>,
    /// Taint branch ratio from `TaintMetrics` - higher means function actually branches on input.
    /// Used by composition layer to suppress hollow validators.
    #[serde(default)]
    pub taint_branch_ratio: Option<f64>,
    /// Whether the function's name indicates a validator/sanitizer
    /// (`validate_input`, `check_*`, `sanitize_*`, ...). From `TaintMetrics`.
    /// Used by composition layer before suppressing high branch-ratio findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_validation_name: Option<bool>,
    /// Per-dimension match breakdown, present when finding comes from corpus matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_evidence: Option<MatchEvidence>,
    /// CWE identifier (e.g. "CWE-918"), from the pattern's [frensense] block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// CVSS v3 score (e.g. 8.8), from the pattern's [frensense] block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f32>,
    /// OWASP Top 10 category (e.g. "A10:2021"), from the pattern's [frensense] block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
}

/// Lossless usize → u32, saturating at `u32::MAX`.
#[inline]
#[must_use]
pub fn to_u32(n: usize) -> u32 {
    u32::try_from(n).expect("file index exceeds u32::MAX")
}

impl Advisory {
    /// Create an advisory with common defaults pre-filled.
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Only set the fields that differ per finding.
    pub fn bare(
        rule_id: impl Into<String>,
        severity: Severity,
        file_id: FileId,
        file_path: &std::path::Path,
        observation: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            file_id,
            file_path: file_path.display().to_string(),
            severity,
            observation: observation.into(),
            confidence: 0.5,
            impact: String::new(),
            improvement: String::new(),
            line: 0,
            column: 0,
            start_byte: 0,
            end_byte: 0,
            original_content: String::new(),
            proposed_replacement: None,
            proposed_import: None,
            enclosing_symbol: None,
            fingerprint: String::new(),
            auto_fixable: false,
            requires_human: true,
            tags: Vec::new(),
            taint_branch_ratio: None,
            has_validation_name: None,
            match_evidence: None,
            cwe: None,
            cvss: None,
            owasp: None,
        }
    }

    pub fn with_confidence(mut self, v: f64) -> Self {
        self.confidence = v;
        self
    }
    pub fn with_line(mut self, v: u32) -> Self {
        self.line = v;
        self
    }
    pub fn with_column(mut self, v: u32) -> Self {
        self.column = v;
        self
    }
    pub fn with_bytes(mut self, start: u32, end: u32) -> Self {
        self.start_byte = start;
        self.end_byte = end;
        self
    }
    pub fn with_content(mut self, v: impl Into<String>) -> Self {
        self.original_content = v.into();
        self
    }
    pub fn with_impact(mut self, v: impl Into<String>) -> Self {
        self.impact = v.into();
        self
    }
    pub fn with_improvement(mut self, v: impl Into<String>) -> Self {
        self.improvement = v.into();
        self
    }
    pub fn with_enclosing_symbol(mut self, v: impl Into<String>) -> Self {
        self.enclosing_symbol = Some(v.into());
        self
    }
    pub fn with_tags<const N: usize>(mut self, tags: [&str; N]) -> Self {
        self.tags = tags.iter().map(std::string::ToString::to_string).collect();
        self
    }
    pub fn with_replacement(mut self, v: impl Into<String>) -> Self {
        self.proposed_replacement = Some(v.into());
        self
    }

    pub fn with_taint_branch_ratio(mut self, v: f64) -> Self {
        self.taint_branch_ratio = Some(v);
        self
    }

    pub fn with_has_validation_name(mut self, v: bool) -> Self {
        self.has_validation_name = Some(v);
        self
    }

    /// Returns a unique identity key for this advisory, used for baseline comparisons.
    #[must_use]
    pub fn identity(&self) -> (String, String, Option<String>, u32, u32) {
        (
            self.rule_id.clone(),
            self.file_path.clone(),
            self.enclosing_symbol.clone(),
            self.line,
            self.column,
        )
    }

    #[must_use]
    pub fn fuzzy_identity(&self) -> (String, String, Option<String>, String) {
        (
            self.rule_id.clone(),
            self.file_path.clone(),
            self.enclosing_symbol.clone(),
            self.original_content.clone(),
        )
    }
}

impl PartialEq for Advisory {
    fn eq(&self, other: &Self) -> bool {
        self.rule_id == other.rule_id
            && self.file_id == other.file_id
            && self.file_path == other.file_path
            && self.severity == other.severity
            && self.confidence.to_bits() == other.confidence.to_bits()
            && self.observation == other.observation
            && self.impact == other.impact
            && self.improvement == other.improvement
            && self.line == other.line
            && self.column == other.column
            && self.start_byte == other.start_byte
            && self.end_byte == other.end_byte
            && self.original_content == other.original_content
            && self.proposed_replacement == other.proposed_replacement
            && self.proposed_import == other.proposed_import
            && self.enclosing_symbol == other.enclosing_symbol
            && self.fingerprint == other.fingerprint
    }
}

impl Eq for Advisory {}

impl std::hash::Hash for Advisory {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.rule_id.hash(state);
        self.file_id.hash(state);
        self.file_path.hash(state);
        self.severity.hash(state);
        self.confidence.to_bits().hash(state);
        self.observation.hash(state);
        self.impact.hash(state);
        self.improvement.hash(state);
        self.line.hash(state);
        self.column.hash(state);
        self.start_byte.hash(state);
        self.end_byte.hash(state);
        self.original_content.hash(state);
        self.proposed_replacement.hash(state);
        self.proposed_import.hash(state);
        self.enclosing_symbol.hash(state);
        self.fingerprint.hash(state);
    }
}

type TaintCacheKey = (String, String, String, String, usize);
type TaintCacheMap = HashMap<TaintCacheKey, Vec<Advisory>>;

const TAINT_CACHE_MAX: usize = 1024;

pub struct TaintCache {
    inner: RefCell<TaintCacheMap>,
    order: RefCell<VecDeque<TaintCacheKey>>,
}

impl TaintCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(HashMap::new()),
            order: RefCell::new(VecDeque::new()),
        }
    }

    pub fn get(&self, key: &TaintCacheKey) -> Option<Vec<Advisory>> {
        self.inner.borrow().get(key).cloned()
    }

    pub fn insert(&self, key: TaintCacheKey, value: Vec<Advisory>) {
        let mut inner = self.inner.borrow_mut();
        let mut order = self.order.borrow_mut();
        if inner.len() >= TAINT_CACHE_MAX
            && let Some(oldest) = order.pop_front()
        {
            inner.remove(&oldest);
        }
        order.push_back(key.clone());
        inner.insert(key, value);
    }
}

impl Default for TaintCache {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FrensenseContext<'a> {
    pub file_id: FileId,
    pub file_path: &'a Path,
    pub source_code: &'a str,
    pub tree: &'a tree_sitter::Tree,
    pub symbols: &'a SymbolRegistry,
    pub graph: &'a crate::semantics::graph::SemanticGraph,
    pub semantic_ops: &'a [crate::semantics::data_flow::normalization::SemanticOp],
    pub taint_cache: &'a TaintCache,
    pub file_trees: &'a rustc_hash::FxHashMap<
        String,
        (
            tree_sitter::Tree,
            String,
            Vec<crate::semantics::data_flow::normalization::SemanticOp>,
        ),
    >,
    pub file_context: frensense_engine::context::FileContext,
    pub taint_confidence_interprocedural: f64,
    pub taint_confidence_intraprocedural: f64,
    pub default_taint_max_depth: usize,
    pub ngram_window_size: usize,
}

pub type FileTreeMap = rustc_hash::FxHashMap<
    String,
    (
        tree_sitter::Tree,
        String,
        Vec<crate::semantics::data_flow::normalization::SemanticOp>,
    ),
>;

impl<'a> FrensenseContext<'a> {
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Create a context with sensible defaults for taint analysis parameters.
    pub fn new(
        file_id: FileId,
        file_path: &'a Path,
        source_code: &'a str,
        tree: &'a tree_sitter::Tree,
        symbols: &'a SymbolRegistry,
        file_trees: &'a FileTreeMap,
        taint_cache: &'a TaintCache,
    ) -> Self {
        Self {
            file_id,
            file_path,
            source_code,
            tree,
            symbols,
            graph: symbols.graph(),
            semantic_ops: &[],
            taint_cache,
            file_trees,
            file_context: frensense_engine::context::FileContext::extract(file_path, source_code),
            taint_confidence_interprocedural: 0.80,
            taint_confidence_intraprocedural: 0.90,
            default_taint_max_depth: 5,
            ngram_window_size: 5,
        }
    }

    /// Create a context for interprocedural resolution, overriding file-level fields
    /// while inheriting taint parameters from the parent context.
    #[must_use]
    pub fn for_interprocedural(
        parent: &'a Self,
        file_id: FileId,
        file_path: &'a Path,
        source_code: &'a str,
        tree: &'a tree_sitter::Tree,
        semantic_ops: &'a [crate::semantics::data_flow::normalization::SemanticOp],
    ) -> Self {
        Self {
            file_id,
            file_path,
            source_code,
            tree,
            symbols: parent.symbols,
            graph: parent.graph,
            semantic_ops,
            taint_cache: parent.taint_cache,
            file_trees: parent.file_trees,
            file_context: frensense_engine::context::FileContext::extract(file_path, source_code),
            taint_confidence_interprocedural: parent.taint_confidence_interprocedural,
            taint_confidence_intraprocedural: parent.taint_confidence_intraprocedural,
            default_taint_max_depth: parent.default_taint_max_depth,
            ngram_window_size: parent.ngram_window_size,
        }
    }
}

/// Core Trait: Represents a high-precision semantic `Frensense` rule.
pub trait FrensenseRule: Send + Sync {
    fn metadata(&self) -> &RuleMetadata;

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// The core logic for verifying a finding.
    fn check<'a>(&self, node: Node<'a>, context: &FrensenseContext<'a>) -> Vec<Advisory>;

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Helper to get rule ID
    fn id(&self) -> &str {
        self.metadata().id.as_ref()
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Helper to check file applicability
    fn applies_to(&self, extension: &str) -> bool;

    /// File-level check (not per-node). Fires once per file.
    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Default no-op - override for rules like file-length limits.
    fn file_check(&self, _context: &FrensenseContext<'_>) -> Vec<Advisory> {
        Vec::new()
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// Helper for query-based matching
    fn query(&self) -> Option<&str> {
        None
    }

    ///
    /// # Panics
    /// May panic if internal assertions fail.
    /// DRY Helper: Create a new advisory for this rule.
    fn new_advisory(
        &self,
        node: &Node,
        context: &FrensenseContext,
        observation: String,
    ) -> Advisory {
        let meta = self.metadata();
        let file_path = context.file_path.to_string_lossy().to_string();
        let enclosing_symbol = context
            .symbols
            .find_function_at(&file_path, node.start_position().row + 1)
            .and_then(|idx| context.symbols.graph().get_symbol(idx))
            .map(|s| s.name.clone());

        let mut adv = Advisory::bare(
            meta.id.as_ref(),
            meta.severity,
            context.file_id,
            context.file_path,
            observation,
        )
        .with_confidence(meta.confidence)
        .with_line(u32::try_from(node.start_position().row + 1).unwrap_or(u32::MAX))
        .with_column(u32::try_from(node.start_position().column + 1).unwrap_or(u32::MAX))
        .with_bytes(
            u32::try_from(node.start_byte()).unwrap_or(u32::MAX),
            u32::try_from(node.end_byte()).unwrap_or(u32::MAX),
        )
        .with_content(&context.source_code[node.start_byte()..node.end_byte()])
        .with_impact(meta.impact.as_ref())
        .with_improvement(meta.improvement.as_ref());
        adv.requires_human = false;
        adv.enclosing_symbol = enclosing_symbol;
        adv.tags = meta.tags.iter().map(ToString::to_string).collect();
        adv
    }

    fn new_remediated_advisory(
        &self,
        node: &Node,
        context: &FrensenseContext,
        observation: String,
        replacement: String,
        import: Option<String>,
    ) -> Advisory {
        let mut adv = self.new_advisory(node, context, observation);
        adv.proposed_replacement = Some(replacement);
        adv.proposed_import = import;
        adv
    }

    fn with_confidence(&self, mut advisory: Advisory, confidence: f64) -> Advisory {
        advisory.confidence = confidence;
        advisory
    }
}

pub use crate::engine::source::SourceRegistry;

#[derive(Error, Debug)]
pub enum FrensenseError {
    #[error("Parse failure: {0}")]
    ParseFailure(String),
    #[error("Rule configuration error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parser error: {0}")]
    Parser(#[from] tree_sitter::LanguageError),
    #[error("Pattern error: {0}")]
    Pattern(String),
    #[error("Engine error: {0}")]
    Engine(String),
}

pub type Result<T> = std::result::Result<T, FrensenseError>;

// Force cargo recompilation of embedded rules definitions
