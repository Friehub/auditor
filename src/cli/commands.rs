#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]
use crate::Result;
use crate::parser::ParserRegistry;
use std::path::Path;

pub fn print_help() {
    println!("Frensense - Example-Driven Code Analysis");
    println!("Version: {}", crate::FRENSENSE_VERSION);
    println!("Detects bugs using corpus patterns instead of handwritten rules.");
    println!();
    println!("Usage: frensense [path] [options]");
    println!();
    println!("Arguments:");
    println!("  path                File or directory to scan (default: current directory)");
    println!();
    println!("Detection Options:");
    println!("  --corpus <dir>      Load detection patterns from corpus directory");
    println!(
        "  --use-compiler      Enable exact semantic resolution (Oxc for TS, rust-analyzer for RS)"
    );

    println!("  --threshold <0-1>   Corpus match threshold (default: 0.40)");
    println!("  --language <lang>   Language filter: rust, typescript, javascript, yaml");
    println!("  --diff-only         Only scan files changed since the last git commit");
    println!("  --severity <level>  Minimum severity: critical, warning, info");
    println!();
    println!("Confidence & Tuning:");
    println!(
        "  --confidence <tier>      Preset: high (>=0.85), medium (>=0.60), low (>=0.30), any"
    );
    println!("  --min-confidence <0-1>   Raw confidence threshold (default: 0.0)");
    println!("  --jaccard-threshold <0-1>  Similarity threshold for duplicate detection");
    println!("  --max-source-lines <N>   Limit source lines for analysis");
    println!();
    println!("Output Options:");
    println!("  --json              Output findings as JSON");
    println!("  --sarif             Output findings in SARIF format");
    println!("  --strict            Exit with code 1 if any findings match filter");
    println!("  --emit-baseline <file>   Save current findings as a baseline");
    println!(
        "  --emit-hypotheses        Write findings as hypotheses.json in the target directory"
    );
    println!("  --compare-baseline <file>  Compare findings against a baseline");
    println!("  --fix [scope]      Apply automated fixes (scope: all, style, security)");
    println!(
        "  --diff [scope]     Show unified diff of proposed changes (scope: all, style, security)"
    );
    println!("  --check-deps       Require cargo metadata for Rust dependency checking");
    println!();
    println!("Style Profile:");
    println!("  --learn-profile     Build a project style profile from current codebase");
    println!("  --check-profile     Check code against learned profile for style anomalies");
    println!(
        "  --profile-threshold <0-1>  Surprise threshold for anomaly detection (default: 0.7)"
    );
    println!("  --profile-stats     Display profile statistics");
    println!();
    println!("Corpus Development:");
    println!("  --build-bundle       Compile the corpus into a binary .frc bundle");
    println!(
        "  --build-bundle-output <file>  Output path for the bundle (default: frensense-corpus.frc)"
    );
    println!();
    println!("Information:");
    println!("  --version           Display version and enabled features");
    println!("  --list-patterns     List loaded corpus patterns and their descriptions");
    println!("  --debug <file>      Dump anonymized AST for a source file");
    println!("                      Test a custom rule against a fixture file");
    println!("                      Optional: --expect-line <N>");
    println!();
    println!("Examples:");
    println!("  frensense                            Scan current directory");
    println!("  frensense src/                       Scan a specific directory");
    println!("  frensense main.rs                    Scan a single file");
    println!("  frensense --language rust .           Scan Rust files only");
    println!("  frensense --diff-only --strict        Check changed files, fail on any finding");
    println!("  frensense --json --suite extended     Export extended scan as JSON");
    println!("  frensense --disable-rule RUST_STD_OUTPUT .    Disable a specific rule");
    println!("  frensense --override-severity FILE_TOO_LONG:info .  Change rule severity");
    println!("  frensense --emit-baseline baseline.json   Save baseline");
    println!("  frensense --compare-baseline baseline.json  Check for regressions");
    println!();
    println!("Learn Mode:");
    println!("  frensense --learn positive.ts negative.ts    Learn patterns from examples");
    println!("  frensense --learn pos.ts neg.ts --learn-output rules/  Output to directory");
    println!();
    println!("Features Enabled:");
    #[cfg(feature = "rust")]
    println!("  [x] Rust Analysis");
    #[cfg(feature = "typescript")]
    println!("  [x] TypeScript/JS Analysis");
    #[cfg(feature = "fingerprinting")]
    println!("  [x] N-Gram Fingerprinting");
    println!("  [x] Auto-Remediation");
}

pub fn print_version() {
    println!(
        "Frensense v{} - Semantic Code Analysis Engine",
        crate::FRENSENSE_VERSION
    );
    println!("Ship with confidence. Audit with insight.");
    println!("\nFeatures Enabled:");
    #[cfg(feature = "rust")]
    println!("  [x] Rust Analysis");
    #[cfg(feature = "typescript")]
    println!("  [x] TypeScript/JS Analysis");
    #[cfg(feature = "fingerprinting")]
    println!("  [x] N-Gram Fingerprinting");
    println!("  [x] Auto-Remediation");
}

pub fn handle_list_rules() -> Result<()> {
    println!("YAML rules replaced by corpus-based detection.");
    println!("Use --list-patterns to see loaded corpus patterns.");
    Ok(())
}

pub fn handle_list_patterns(corpus_dir: Option<&str>) -> Result<()> {
    use frensense_bundler::loader::load_corpus;
    let dir = corpus_dir.unwrap_or("corpus/targets");
    let path = std::path::Path::new(dir);
    if !path.exists() {
        println!("Corpus directory not found: {dir}");
        println!("Create one with: mkdir -p corpus/targets/");
        println!("Then add positive/negative example pairs.");
        return Ok(());
    }
    match load_corpus(path).map(|(p, _)| p) {
        Ok(patterns) => {
            println!("Loaded {} corpus patterns from {dir}:", patterns.len());
            for p in &patterns {
                println!("  {}", p.id);
            }
        }
        Err(e) => println!("Error loading corpus: {e}"),
    }
    Ok(())
}

pub fn handle_debug_ast(file_path: &str) -> Result<()> {
    let path = Path::new(file_path);
    let content = std::fs::read_to_string(path).expect("Failed to read file");
    let mut parser = tree_sitter::Parser::new();
    let language = ParserRegistry::get_language(path).expect("Unsupported language");
    parser
        .set_language(&language)
        .expect("Failed to set language");
    let tree = parser.parse(&content, None).expect("Parse failure");
    println!("Anonymized AST for {file_path}:\n");
    println!("{}", tree.root_node().to_sexp());
    std::process::exit(0);
}

pub fn handle_generate_docs() -> Result<()> {
    println!("YAML rules replaced by corpus. No rule docs to generate.");
    Ok(())
}

pub fn handle_early_args(args: &[String]) -> bool {
    if args.len() < 2 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help();
        std::process::exit(0);
    }

    if args.contains(&"--version".to_string()) {
        print_version();
        std::process::exit(0);
    }

    if args.contains(&"--generate-docs".to_string()) {
        if let Err(e) = handle_generate_docs() {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return true;
    }

    if let Some(pos) = args.iter().position(|a| a == "--debug")
        && let Some(file_path) = args.get(pos + 1)
    {
        if let Err(e) = handle_debug_ast(file_path) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return true;
    }

    if args.contains(&"--list-rules".to_string()) || args.contains(&"--list-patterns".to_string()) {
        let corpus_dir = args
            .iter()
            .position(|a| a == "--corpus")
            .and_then(|i| args.get(i + 1).map(std::string::String::as_str));
        if let Err(e) = handle_list_patterns(corpus_dir) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return true;
    }

    false
}
