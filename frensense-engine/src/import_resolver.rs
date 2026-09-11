// SPDX-License-Identifier: MIT

//! Per-file import map that resolves type names to their source packages.
//!
//! When a file has `import { Request } from 'express'`, this records
//! `"Request" → "express"`.  Without this, `Request` is ambiguous
//! (could be express.Request, node-fetch.Request, or a local type).
//! With the import map, any parameter typed `Request` is unambiguously
//! an Express request, so `is_http_handler` can use it as a signal.

use rustc_hash::FxHashMap;
use tree_sitter::Node;

/// Maps imported names (as they appear in type annotations) to their
/// originating package name.
///
/// Built once per file during `analyze_file`.  Used by `classify_role`
/// to resolve ambiguous type annotations like `Request` → `express`.
#[derive(Debug, Clone, Default)]
pub struct ImportMap {
    /// `name → package`, e.g. `"Request" → "express"`
    pub name_to_package: FxHashMap<String, String>,
}

impl ImportMap {
    pub fn new() -> Self {
        Self {
            name_to_package: FxHashMap::default(),
        }
    }

    /// Resolve an imported name to its source package.
    pub fn resolve(&self, type_name: &str) -> Option<&str> {
        self.name_to_package.get(type_name).map(|s| s.as_str())
    }

    /// Returns true when the given type name is known to be imported
    /// from the given package.
    pub fn is_imported_from(&self, type_name: &str, package: &str) -> bool {
        self.name_to_package
            .get(type_name)
            .is_some_and(|p| p == package)
    }

    /// Build the import map from a file's root AST node.
    ///
    /// Handles the following tree-sitter import patterns:
    /// - `import { A } from 'pkg'`            (named import)
    /// - `import { A as B } from 'pkg'`       (aliased named import → stores both `B` and `A`)
    /// - `import A from 'pkg'`                (default import → stores `A`)
    /// - `import * as A from 'pkg'`           (namespace import → stores `A`)
    /// - `import type { A } from 'pkg'`       (type import — same shape as named)
    /// - `import 'pkg'`                       (side-effect — no bindings, skipped)
    pub fn build_from_tree(ext: &str, source: &str, root: Node) -> Self {
        let mut map = Self::new();
        if let Some(spec) = frensense_lang::spec_for_ext(ext) {
            for import in spec.extract_imports(root, source) {
                map.name_to_package
                    .insert(import.local_name, import.package.clone());
                if let Some(symbol) = import.symbol {
                    map.name_to_package.insert(symbol, import.package);
                }
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_empty() {
        let map = ImportMap::new();
        assert!(map.name_to_package.is_empty());
    }

    #[test]
    fn test_resolve_unknown() {
        let map = ImportMap::new();
        assert_eq!(map.resolve("Request"), None);
    }

    #[test]
    fn test_entry_point_not_imported() {
        let map = ImportMap::new();
        assert_eq!(map.classify_entry_point("Request"), EntryPointKind::Unknown);
    }
}

/// Categorizes what kind of entry point a function is based on its
/// imported parameter types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPointKind {
    HttpRequestResponse,
    HttpRequestOnly,
    EventConsumer,
    QueueConsumer,
    WebhookReceiver,
    GrpcHandler,
    WebSocketHandler,
    Unknown,
}

static PACKAGE_HTTP_TYPES: &[(&str, &str, EntryPointKind)] = &[
    ("express", "Request", EntryPointKind::HttpRequestResponse),
    ("express", "Response", EntryPointKind::HttpRequestResponse),
    (
        "express",
        "NextFunction",
        EntryPointKind::HttpRequestResponse,
    ),
    (
        "fastify",
        "FastifyRequest",
        EntryPointKind::HttpRequestResponse,
    ),
    (
        "fastify",
        "FastifyReply",
        EntryPointKind::HttpRequestResponse,
    ),
    (
        "next/server",
        "NextRequest",
        EntryPointKind::HttpRequestOnly,
    ),
    (
        "next/server",
        "NextResponse",
        EntryPointKind::HttpRequestOnly,
    ),
    (
        "aws-lambda",
        "APIGatewayProxyEvent",
        EntryPointKind::HttpRequestResponse,
    ),
    ("aws-lambda", "SQSEvent", EntryPointKind::EventConsumer),
    ("aws-lambda", "S3Event", EntryPointKind::EventConsumer),
    (
        "@nestjs/common",
        "ExecutionContext",
        EntryPointKind::HttpRequestResponse,
    ),
    ("hono", "Context", EntryPointKind::HttpRequestResponse),
    ("hono", "HonoRequest", EntryPointKind::HttpRequestOnly),
    ("koa", "Context", EntryPointKind::HttpRequestResponse),
    (
        "@grpc/grpc-js",
        "ServerUnaryCall",
        EntryPointKind::GrpcHandler,
    ),
    ("ws", "WebSocket", EntryPointKind::WebSocketHandler),
    (
        "kafkajs",
        "EachMessagePayload",
        EntryPointKind::QueueConsumer,
    ),
    ("stripe", "Event", EntryPointKind::WebhookReceiver),
];

impl ImportMap {
    pub fn classify_entry_point(&self, type_name: &str) -> EntryPointKind {
        let pkg = match self.name_to_package.get(type_name) {
            Some(p) => p.as_str(),
            None => return EntryPointKind::Unknown,
        };
        for &(table_pkg, table_type, ref kind) in PACKAGE_HTTP_TYPES {
            if pkg == table_pkg && type_name == table_type {
                return *kind;
            }
        }
        EntryPointKind::Unknown
    }

    pub fn has_http_entry_point(&self, type_usages: &[String]) -> bool {
        type_usages.iter().any(|t| {
            matches!(
                self.classify_entry_point(t),
                EntryPointKind::HttpRequestResponse | EntryPointKind::HttpRequestOnly
            )
        })
    }
}
