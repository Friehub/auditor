// SPDX-License-Identifier: MIT

use frensense_lang::NodeRole;

use crate::lang::Language;
use crate::lang::kinds::AbstractKind;

/// Map a tree-sitter node kind to an [`AbstractKind`] using the
/// [`frensense_lang`] registry as the single source of truth.
///
/// Previously this function contained six separate per-language match arms
/// (Rust, TypeScript, JavaScript, C, Python, Go). Now it delegates to
/// `Language::spec().classify()` and bridges `NodeRole` → `AbstractKind`.
pub fn abstract_kind(ts_kind: &str, language: Language) -> AbstractKind {
    // If we have a spec for this language, use it.
    if let Some(spec) = language.spec() {
        return node_role_to_abstract_kind(spec.classify(ts_kind), ts_kind, language);
    }

    // Html has no spec registered; keep a minimal inline map.
    match ts_kind {
        "element" | "script_element" | "style_element" => AbstractKind::Block,
        "text" | "doctype" => AbstractKind::StringLiteral,
        _ => AbstractKind::Other,
    }
}

/// Convert a [`NodeRole`] (from frensense-lang) into the engine's
/// [`AbstractKind`] (used for structural hashing in the fingerprinter).
///
/// `NodeRole` is the canonical, language-agnostic classification.
/// `AbstractKind` is a slightly different enumeration that the engine has
/// been using for structural n-grams. This bridge keeps both working while
/// the engine migrates incrementally.
fn node_role_to_abstract_kind(role: NodeRole, ts_kind: &str, language: Language) -> AbstractKind {
    match role {
        // ── Definitions ──────────────────────────────────────────────────
        NodeRole::Function {
            is_method: true, ..
        } => AbstractKind::MethodDef,
        NodeRole::Function {
            is_method: false, ..
        } => {
            // Closures and lambdas still want Closure in the abstract kind
            let is_closure = matches!(
                ts_kind,
                "arrow_function"
                    | "closure_expression"
                    | "func_literal"
                    | "lambda"
                    | "function_expression"
                    | "async_function_expression"
            );
            if is_closure {
                AbstractKind::Closure
            } else {
                AbstractKind::FunctionDef
            }
        }

        // ── Declarations / assignments ───────────────────────────────────
        NodeRole::Declaration { .. } => AbstractKind::Assign,
        NodeRole::Assignment { .. } => AbstractKind::Assign,

        // ── Calls ────────────────────────────────────────────────────────
        NodeRole::Call { .. } => AbstractKind::Call,
        NodeRole::MemberAccess { .. } => AbstractKind::MethodCall,

        // ── Control flow ─────────────────────────────────────────────────
        NodeRole::Branch => AbstractKind::Conditional,
        NodeRole::Loop => AbstractKind::Loop,
        NodeRole::Return => AbstractKind::Return,
        NodeRole::Try | NodeRole::Catch | NodeRole::Finally => AbstractKind::TryCatch,
        NodeRole::Throw => AbstractKind::Throw,
        NodeRole::ErrorGuard => AbstractKind::Conditional,
        NodeRole::ErrorPropagation => AbstractKind::TryCatch,
        NodeRole::ContextManager => AbstractKind::TryCatch,
        NodeRole::Await => AbstractKind::Await,

        // ── Structural ───────────────────────────────────────────────────
        NodeRole::Block => AbstractKind::Block,
        NodeRole::Import => AbstractKind::ImportDecl,
        NodeRole::Export => AbstractKind::ExportDecl,
        NodeRole::Identifier => AbstractKind::Identifier,
        NodeRole::Literal => {
            // Distinguish string vs number vs bool using the raw ts_kind.
            // This preserves the fingerprint granularity that existing corpus
            // entries were built with.
            match ts_kind {
                "string"
                | "string_literal"
                | "raw_string_literal"
                | "template_string"
                | "interpreted_string_literal"
                | "string_fragment"
                | "char_literal" => AbstractKind::StringLiteral,

                "number" | "integer_literal" | "float_literal" | "int_literal"
                | "number_literal" => AbstractKind::NumberLiteral,

                "true" | "false" | "boolean_literal" | "none" => AbstractKind::BoolLiteral,

                _ => AbstractKind::StringLiteral,
            }
        }

        // ── Language-specific extras via raw ts_kind ─────────────────────
        // NodeRole::Other covers things the lang spec doesn't classify.
        // We still want to catch a few engine-specific extras per language.
        NodeRole::Other => other_to_abstract_kind(ts_kind, language),
    }
}

/// Fallback handler for `NodeRole::Other` — maps a small set of language-
/// specific node kinds that `AbstractKind` tracks but `NodeRole` doesn't have
/// a variant for (e.g. struct/enum/trait definitions, unsafe blocks).
fn other_to_abstract_kind(ts_kind: &str, language: Language) -> AbstractKind {
    match language {
        Language::Rust => match ts_kind {
            "struct_item" => AbstractKind::StructDef,
            "enum_item" => AbstractKind::EnumDef,
            "trait_item" => AbstractKind::InterfaceDef,
            "const_item" => AbstractKind::ConstDef,
            "mod_item" => AbstractKind::ModuleDef,
            "impl_item" => AbstractKind::ClassDef,
            "unsafe_block" => AbstractKind::Unsafe,
            "async_block" => AbstractKind::Async,
            "match_expression" => AbstractKind::Match,
            "parameters" | "self_parameter" | "parameter" => AbstractKind::Parameters,
            "arguments" => AbstractKind::Arguments,
            "binary_expression" => AbstractKind::BinaryOp,
            "unary_expression" => AbstractKind::UnaryOp,
            "type_identifier"
            | "primitive_type"
            | "scoped_identifier"
            | "scoped_type_identifier" => AbstractKind::Identifier,
            _ => AbstractKind::Other,
        },
        Language::TypeScript | Language::JavaScript => match ts_kind {
            "class_declaration" => AbstractKind::ClassDef,
            "interface_declaration" => AbstractKind::InterfaceDef,
            "enum_declaration" => AbstractKind::EnumDef,
            "switch_statement" => AbstractKind::Match,
            "formal_parameters" => AbstractKind::Parameters,
            "arguments" => AbstractKind::Arguments,
            "binary_expression" => AbstractKind::BinaryOp,
            "unary_expression" => AbstractKind::UnaryOp,
            "type_annotation" | "type_arguments" => AbstractKind::Other,
            _ => AbstractKind::Other,
        },
        Language::Python => match ts_kind {
            "class_definition" => AbstractKind::ClassDef,
            "match_statement" => AbstractKind::Match,
            "parameters" => AbstractKind::Parameters,
            "argument_list" => AbstractKind::Arguments,
            "binary_operator" => AbstractKind::BinaryOp,
            "unary_operator" => AbstractKind::UnaryOp,
            "type" => AbstractKind::TypeAnnotation,
            _ => AbstractKind::Other,
        },
        Language::Go => match ts_kind {
            "expression_switch_statement" | "type_switch_statement" => AbstractKind::Match,
            "defer_statement" | "go_statement" => AbstractKind::Call,
            "parameter_list" => AbstractKind::Parameters,
            "argument_list" => AbstractKind::Arguments,
            "binary_expression" => AbstractKind::BinaryOp,
            "unary_expression" => AbstractKind::UnaryOp,
            "field_identifier" | "type_identifier" => AbstractKind::Identifier,
            _ => AbstractKind::Other,
        },
        Language::C => match ts_kind {
            "parameter_list" | "parameter_declaration" => AbstractKind::Parameters,
            "argument_list" => AbstractKind::Arguments,
            "binary_expression" => AbstractKind::BinaryOp,
            "unary_expression" => AbstractKind::UnaryOp,
            _ => AbstractKind::Other,
        },
        Language::Html => AbstractKind::Other,
    }
}
