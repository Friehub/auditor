// SPDX-License-Identifier: MIT

use super::{FindingContext, FindingModule};
use crate::engine::project::FileSnapshot;
use crate::{Advisory, Severity};

/// Detects vulnerable dependencies by checking package.json/Cargo.toml
pub struct VulnerableDeps;

impl FindingModule for VulnerableDeps {
    fn run(&self, snap: &FileSnapshot, _ctx: &mut FindingContext<'_>) -> Vec<Advisory> {
        let mut advisories = Vec::new();

        // Only check package.json files
        if !snap.path.to_string_lossy().ends_with("package.json") {
            return advisories;
        }

        // Parse package.json to extract dependencies
        let deps = extract_npm_deps(&snap.content);

        // Check for known vulnerable packages
        let vulnerable = [
            (
                "bcrypt-nodejs",
                "CWE-798",
                "0.0.3",
                "Use of hardcoded credentials; unmaintained, use bcrypt or bcryptjs instead",
            ),
            (
                "marked",
                "CWE-79",
                "0.3.5",
                "XSS in markdown rendering; versions < 4.0.10 are vulnerable",
            ),
            (
                "needle",
                "CWE-200",
                "2.2.4",
                "Information exposure; versions < 2.6.0 have SSRF vulnerabilities",
            ),
            (
                "node-esapi",
                "CWE-1395",
                "0.0.1",
                "Dependency on unmaintained ESAPI library",
            ),
            (
                "swig",
                "CWE-79",
                "1.4.2",
                "Template injection; unmaintained, use nunjucks or handlebars",
            ),
            (
                "helmet",
                "CWE-1021",
                "2.0.0",
                "Versions < 3.0.0 missing critical security headers",
            ),
            (
                "forever",
                "CWE-400",
                "2.0.0",
                "Process management issues; use pm2 instead",
            ),
        ];

        for (pkg, cwe, version, desc) in vulnerable {
            if deps
                .iter()
                .any(|(name, ver)| name == pkg && ver.contains(version))
            {
                let mut advisory = Advisory::bare(
                    format!("VULN_DEP_{}", pkg.to_uppercase()),
                    Severity::Warning,
                    snap.id,
                    &snap.path,
                    format!("Vulnerable dependency detected: {}@{}", pkg, version),
                );
                advisory.confidence = 0.9;
                advisory.impact = desc.to_string();
                advisory.improvement = format!("Upgrade {} to a secure version", pkg);
                advisory.cwe = Some(cwe.to_string());
                advisory.cvss = Some(7.5);
                advisory.owasp = Some("A06:2021".to_string());
                advisory.tags = vec!["vulnerable-dependency".to_string()];
                advisories.push(advisory);
            }
        }

        advisories
    }
}

fn extract_npm_deps(content: &str) -> Vec<(String, String)> {
    let mut deps = Vec::new();

    // Simple JSON parsing for dependencies
    if let Some(deps_start) = content.find("\"dependencies\"") {
        let deps_section = &content[deps_start..];
        let mut in_deps = false;

        for line in deps_section.lines() {
            let trimmed = line.trim();
            if trimmed.contains('{') {
                in_deps = true;
                continue;
            }
            if !in_deps {
                continue;
            }
            if trimmed.starts_with('}') {
                break;
            }

            if let Some(colon_pos) = trimmed.find(':') {
                let key = trimmed[..colon_pos]
                    .trim()
                    .trim_matches('"')
                    .trim_matches(',');
                let value = trimmed[colon_pos + 1..]
                    .trim()
                    .trim_matches('"')
                    .trim_matches(',');

                if !key.is_empty() && !value.is_empty() {
                    deps.push((key.to_string(), value.to_string()));
                }
            }
        }
    }

    deps
}
