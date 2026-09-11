// SPDX-License-Identifier: MIT

use std::path::Path;

const TEST_PATH_KEYWORDS: &[&str] = &["test", "spec", "cypress", "__tests__", "tests/"];
const TEST_ENV_KEYWORDS: &[&str] = &[
    // JS/TS
    "describe(",
    " it(",
    "\nit(",
    "test(",
    // Rust
    "#[test]",
    "#[tokio::test]",
    "cfg(test)",
    // Go
    "func test",
    "testing.t",
    // Java / C#
    "@test",
    "[test]",
    "[fact]",
    // C / C++ (GTest)
    "test(",
    "test_f(",
    "expect_eq(",
    "assert_eq(",
];
const MOCK_PATH_KEYWORDS: &[&str] = &["mock", "stub"];
const CONFIG_PATH_KEYWORDS: &[&str] = &["config", "settings"];

const ROUTE_PATH_KEYWORDS: &[&str] = &["route", "controller", "handler", "endpoint", "api/"];
const ROUTE_ENV_KEYWORDS: &[&str] = &[
    // JS/TS (Express/Fastify)
    "(req, res)",
    "(req, res,",
    "(req, res ",
    "req: request",
    "request, response",
    "app.get(",
    "app.post(",
    "app.put(",
    "app.delete(",
    "app.patch(",
    "router.get(",
    "router.post(",
    "router.put(",
    "router.delete(",
    "router.patch(",
    "res.send",
    "res.json",
    "res.redirect",
    "res.render",
    "res.status",
    "c.req",
    "router.",
    // Go (net/http, Gin, Echo)
    "http.responsewriter",
    "*http.request",
    "http.handlefunc",
    "gin.context",
    "echo.context",
    "c.json",
    // Rust (Actix, Rocket, Axum)
    "#[get(",
    "#[post(",
    "actix_web",
    "rocket::",
    "axum::",
    "httpresponse",
    "impl responder",
    // Java (Spring)
    "@getmapping",
    "@postmapping",
    "@requestmapping",
    "httpservletrequest",
    "responseentity",
    // C# (ASP.NET)
    "[httpget]",
    "[httppost]",
    "[route(",
    "controllerbase",
    "iactionresult",
];

const UTILITY_PATH_KEYWORDS: &[&str] = &["lib", "util", "helper"];

const SENSITIVITY_HIGH_KEYWORDS: &[&str] =
    &["password", "secret", "jwt", "token", "creditcard", "apikey"];
const SENSITIVITY_MEDIUM_KEYWORDS: &[&str] = &["email", "user", "profile"];
const SENSITIVITY_LOW_KEYWORDS: &[&str] = &["version", "metric", "telemetry"];

#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Environment {
    #[default]
    Unknown,
    Test,
    Mock,
    RouteHandler,
    Utility,
    Config,
}

#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DataSensitivity {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileContext {
    pub environment: Environment,
    pub sensitivity: DataSensitivity,
    pub frameworks: Vec<String>,
}

impl FileContext {
    #[must_use]
    pub fn extract(file_path: &Path, content: &str) -> Self {
        Self::extract_with_spec(file_path, content, None)
    }

    /// Like [`extract`](Self::extract) but prefers per-language context hints
    /// from the spec when available.  Falls back to the hardcoded keyword
    /// lists for any category not covered by the spec.
    #[must_use]
    pub fn extract_with_spec(
        file_path: &Path,
        content: &str,
        spec: Option<&dyn frensense_lang::LanguageSpec>,
    ) -> Self {
        let path_str = file_path.to_string_lossy().to_lowercase();

        let mut env = Environment::Unknown;
        let c = content.to_lowercase();

        // Collect spec-provided test context hints (if any) and merge with
        // the hardcoded list so the hardcoded keywords act as a fallback.
        let spec_test_hints: Vec<String> = spec
            .map(|s| {
                s.test_context_hints()
                    .iter()
                    .map(|h| h.to_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        let test_env_match = spec_test_hints.iter().any(|k| c.contains(k))
            || TEST_ENV_KEYWORDS.iter().any(|k| c.contains(k));

        if TEST_PATH_KEYWORDS.iter().any(|k| path_str.contains(k)) || test_env_match {
            env = Environment::Test;
        } else if MOCK_PATH_KEYWORDS.iter().any(|k| path_str.contains(k)) {
            env = Environment::Mock;
        } else if CONFIG_PATH_KEYWORDS.iter().any(|k| path_str.contains(k)) {
            env = Environment::Config;
        } else {
            // Collect spec-provided route context hints (if any) and merge
            // with the hardcoded list.
            let spec_route_hints: Vec<String> = spec
                .map(|s| {
                    s.route_context_hints()
                        .iter()
                        .map(|h| h.to_lowercase())
                        .collect()
                })
                .unwrap_or_default();
            let route_env_match = spec_route_hints.iter().any(|k| c.contains(k))
                || ROUTE_ENV_KEYWORDS.iter().any(|k| c.contains(k));

            if ROUTE_PATH_KEYWORDS.iter().any(|k| path_str.contains(k)) || route_env_match {
                env = Environment::RouteHandler;
            } else if UTILITY_PATH_KEYWORDS.iter().any(|k| path_str.contains(k)) {
                env = Environment::Utility;
            }
        }

        let mut sensitivity = DataSensitivity::Unknown;
        if SENSITIVITY_HIGH_KEYWORDS.iter().any(|k| c.contains(k)) {
            sensitivity = DataSensitivity::High;
        } else if SENSITIVITY_MEDIUM_KEYWORDS.iter().any(|k| c.contains(k)) {
            sensitivity = DataSensitivity::Medium;
        } else if SENSITIVITY_LOW_KEYWORDS.iter().any(|k| c.contains(k)) {
            sensitivity = DataSensitivity::Low;
        }

        let mut frameworks = Vec::new();
        if c.contains("express") || c.contains("req") && c.contains("res") {
            frameworks.push("Express".to_string());
        }
        if c.contains("react") || c.contains("jsx") {
            frameworks.push("React".to_string());
        }
        if c.contains("gin") || c.contains("echo") {
            frameworks.push("GoWeb".to_string());
        }
        if c.contains("actix") || c.contains("rocket") || c.contains("axum") {
            frameworks.push("RustWeb".to_string());
        }
        if c.contains("spring") || c.contains("controller") {
            frameworks.push("Spring".to_string());
        }

        Self {
            environment: env,
            sensitivity,
            frameworks,
        }
    }
}
