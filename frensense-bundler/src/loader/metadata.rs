use super::types::AdvisoryText;

pub(crate) fn synthesize_advisory(
    pattern_id: &str,
    required_calls: &[String],
    forbidden_calls: &[String],
) -> AdvisoryText {
    // Convert pattern_id like "ts_jwt_bypass" to a readable label
    let label = pattern_id.replace('_', " ");
    let observation = if required_calls.is_empty() {
        format!("Pattern '{label}' matches a known vulnerability shape.")
    } else {
        format!(
            "Function calls {}. This matches a known vulnerability ({label}).",
            required_calls.join(", ")
        )
    };
    let improvement = if forbidden_calls.is_empty() {
        "Review the function against the corpus positive example.".to_string()
    } else {
        format!(
            "Replace {} with {} and validate all inputs.",
            required_calls.join(" / "),
            forbidden_calls.join(" / ")
        )
    };
    AdvisoryText {
        observation: Some(observation),
        impact: None,
        improvement: Some(improvement),
        expected_context: None,
        cwe: None,
        cvss: None,
        owasp: None,
        severity: None,
        runtime_probe: None,
    }
}

/// Parse a `/// [frensense]` / `// [frensense]` / `# [frensense]` block from source.
///
/// Format:
/// ```text
/// [frensense]
/// observation: what the bug looks like
/// impact: what goes wrong
/// improvement: how to fix it
/// ```
///
/// Block ends at the first blank comment line or a non-comment line.
pub(crate) fn parse_frensense_block(source: &str) -> AdvisoryText {
    let mut result = AdvisoryText::default();
    let mut in_block = false;

    for line in source.lines() {
        let trimmed = line.trim();

        // Detect comment prefix
        let content = if let Some(c) = trimmed.strip_prefix("///") {
            Some(c.trim())
        } else if let Some(c) = trimmed.strip_prefix("//!") {
            Some(c.trim())
        } else if let Some(c) = trimmed.strip_prefix("//") {
            Some(c.trim())
        } else {
            trimmed.strip_prefix("#").map(str::trim)
        };

        let Some(text) = content else {
            // Non-comment line — block is over
            break;
        };

        if !in_block {
            if text == "[frensense]" {
                in_block = true;
            }
            continue;
        }

        // Empty comment line ends the block
        if text.is_empty() {
            break;
        }

        if let Some((key, value)) = text.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();
            if !value.is_empty() {
                match key.as_str() {
                    "observation" => result.observation = Some(value),
                    "impact" => result.impact = Some(value),
                    "improvement" => result.improvement = Some(value),
                    "cwe" => result.cwe = Some(value),
                    "cvss" => result.cvss = value.parse::<f32>().ok(),
                    "owasp" => result.owasp = Some(value),
                    "severity" => result.severity = Some(value),
                    "runtime_probe" => result.runtime_probe = Some(value),
                    _ => {}
                }
            }
        }
    }

    result
}

pub(crate) fn load_sidecar_toml(corpus_dir: &std::path::Path, pattern_name: &str) -> AdvisoryText {
    let toml_path = corpus_dir.join(format!("{pattern_name}.toml"));
    let Ok(content) = std::fs::read_to_string(&toml_path) else {
        return AdvisoryText::default();
    };

    let Ok(doc) = content.parse::<toml::Table>() else {
        return AdvisoryText::default();
    };

    let expected_context = doc
        .get("expected_context")
        .and_then(|t| t.as_table())
        .map(|t| {
            let env_str = t
                .get("environment")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let sens_str = t
                .get("sensitivity")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");

            let env = match env_str {
                "Test" => frensense_engine::context::Environment::Test,
                "Mock" => frensense_engine::context::Environment::Mock,
                "RouteHandler" => frensense_engine::context::Environment::RouteHandler,
                "Utility" => frensense_engine::context::Environment::Utility,
                "Config" => frensense_engine::context::Environment::Config,
                _ => frensense_engine::context::Environment::Unknown,
            };

            let sens = match sens_str {
                "Low" => frensense_engine::context::DataSensitivity::Low,
                "Medium" => frensense_engine::context::DataSensitivity::Medium,
                "High" => frensense_engine::context::DataSensitivity::High,
                _ => frensense_engine::context::DataSensitivity::Unknown,
            };

            let frameworks = t
                .get("frameworks")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            frensense_engine::context::FileContext {
                environment: env,
                sensitivity: sens,
                frameworks,
            }
        });

    AdvisoryText {
        observation: doc
            .get("observation")
            .and_then(|v| v.as_str())
            .map(String::from),
        impact: doc.get("impact").and_then(|v| v.as_str()).map(String::from),
        improvement: doc
            .get("improvement")
            .and_then(|v| v.as_str())
            .map(String::from),
        expected_context,
        cwe: doc.get("cwe").and_then(|v| v.as_str()).map(String::from),
        cvss: doc.get("cvss").and_then(|v| v.as_float().map(|f| f as f32)),
        owasp: doc.get("owasp").and_then(|v| v.as_str()).map(String::from),
        severity: doc
            .get("severity")
            .and_then(|v| v.as_str())
            .map(String::from),
        runtime_probe: doc
            .get("runtime_probe")
            .and_then(|v| v.as_str())
            .map(String::from),
    }
}
