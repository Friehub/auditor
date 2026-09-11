// SPDX-License-Identifier: MIT

pub mod kinds;
pub mod mapper;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Rust,
    TypeScript,
    JavaScript,
    C,
    Python,
    Go,
    #[allow(dead_code)]
    Html,
}

impl Language {
    /// Return the [`frensense_lang::LanguageSpec`] for this language.
    ///
    /// Returns `None` only for `Html`, which does not have a spec registered
    /// in `frensense-lang` by default.
    pub fn spec(self) -> Option<&'static dyn frensense_lang::LanguageSpec> {
        let ext = match self {
            Language::Rust => "rs",
            Language::TypeScript => "ts",
            Language::JavaScript => "js",
            Language::C => "c",
            Language::Python => "py",
            Language::Go => "go",
            Language::Html => return None,
        };
        frensense_lang::spec_for_ext(ext)
    }
}
