use frensense_engine::corpus::semantic::SemanticFilter;
use frensense_engine::fingerprint::FunctionFingerprint;

#[derive(Debug, Clone)]
pub struct CorpusPattern {
    pub id: String,
    pub positives: Vec<FunctionFingerprint>,
    pub negatives: Vec<FunctionFingerprint>,
    pub semantic_filter: Option<SemanticFilter>,
    pub observation: Option<String>,
    pub impact: Option<String>,
    pub improvement: Option<String>,
    pub expected_context: Option<frensense_engine::context::FileContext>,
    pub cwe: Option<String>,
    pub cvss: Option<f32>,
    pub owasp: Option<String>,
    pub severity: Option<String>,
    pub runtime_probe: Option<String>,
}

/// A non-fatal diagnostic produced during corpus loading.
/// Callers must surface these to the user — silent coverage gaps are a production risk.
#[derive(Debug, Clone)]
pub struct LoadWarning {
    pub pattern_id: String,
    pub message: String,
}

impl std::fmt::Display for LoadWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "corpus[{}]: {}", self.pattern_id, self.message)
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct AdvisoryText {
    pub(crate) observation: Option<String>,
    pub(crate) impact: Option<String>,
    pub(crate) improvement: Option<String>,
    pub(crate) expected_context: Option<frensense_engine::context::FileContext>,
    pub(crate) cwe: Option<String>,
    pub(crate) cvss: Option<f32>,
    pub(crate) owasp: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) runtime_probe: Option<String>,
}
