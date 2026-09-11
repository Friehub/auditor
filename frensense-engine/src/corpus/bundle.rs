use crate::auto_filter::AutoFilterEntry;
use crate::fingerprint::FunctionFingerprint;
use frensense_frc::BundleHeader;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BundlePattern {
    pub id: String,
    pub positives: Vec<FunctionFingerprint>,
    pub negatives: Vec<FunctionFingerprint>,
    #[serde(default)]
    pub semantic_filter: Option<crate::corpus::semantic::SemanticFilter>,
    #[serde(default)]
    pub observation: Option<String>,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub improvement: Option<String>,
    #[serde(default)]
    pub expected_context: Option<crate::context::FileContext>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub cvss: Option<f32>,
    #[serde(default)]
    pub owasp: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub runtime_probe: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Bundle {
    pub header: BundleHeader,
    pub patterns: Vec<BundlePattern>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BundlePayload {
    pub patterns: Vec<BundlePattern>,
    #[serde(default)]
    pub api_idf_weights: Vec<(u64, f32)>,
    #[serde(default)]
    pub category_weights: Vec<(String, [f64; 15])>,
    #[serde(default)]
    pub auto_filter_stats: Vec<AutoFilterEntry>,
    #[serde(default)]
    pub pattern_calibration: Vec<(String, f32, f32)>,
}

pub struct LoadedBundle {
    pub patterns: Vec<BundlePattern>,
    pub api_idf_weights: Vec<(u64, f32)>,
    pub category_weights: Vec<(String, [f64; 15])>,
    pub auto_filter_stats: Vec<AutoFilterEntry>,
    pub pattern_calibration: Vec<(String, f32, f32)>,
}

pub fn load_bundle(bytes: &[u8]) -> Result<LoadedBundle, String> {
    let (
        header,
        patterns,
        api_idf_weights,
        category_weights,
        auto_filter_stats,
        pattern_calibration,
    ) = match frensense_frc::read_bundle::<BundlePayload>(bytes) {
        Ok((h, payload)) => (
            h,
            payload.patterns,
            payload.api_idf_weights,
            payload.category_weights,
            payload.auto_filter_stats,
            payload.pattern_calibration,
        ),
        Err(e) => match frensense_frc::read_bundle::<Vec<BundlePattern>>(bytes) {
            Ok((h, patterns)) => (h, patterns, Vec::new(), Vec::new(), Vec::new(), Vec::new()),
            Err(_) => return Err(format!("Failed to deserialize bundle: {}", e)),
        },
    };

    if patterns.len() < header.pattern_count as usize {
        tracing::warn!(
            "bundle pattern count mismatch (expected {}, loaded {})",
            header.pattern_count,
            patterns.len()
        );
    }

    Ok(LoadedBundle {
        patterns,
        api_idf_weights,
        category_weights,
        auto_filter_stats,
        pattern_calibration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_version_check() {
        let bytes = vec![b'F', b'R', b'C', b'1'];
        assert!(load_bundle(&bytes).is_err());
    }
}
