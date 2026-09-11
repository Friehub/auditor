import re

with open("src/cli/commands.rs", "r") as f:
    content = f.read()

# First conflict
content = re.sub(
    r'<<<<<<< HEAD\n\s*println!\(\n\s*"  --corpus <dir>      Path to corpus targets directory \(default: corpus/targets\)"\n\s*\);\n=======\n\s*println!\("  --use-compiler      Enable exact semantic resolution \(Oxc for TS, rust-analyzer for RS\)"\);\n>>>>>>> origin/main',
    r'    println!("  --corpus <dir>      Path to corpus targets directory (default: corpus/targets)");\n    println!("  --use-compiler      Enable exact semantic resolution (Oxc for TS, rust-analyzer for RS)");',
    content
)

# Second conflict
content = re.sub(
    r'<<<<<<< HEAD\n\s*println!\(\n\s*"  --build-bundle-output <file>  Output path for the bundle \(default: frensense-corpus.frc\)"\n\s*\);\n=======\n\s*println!\("  --build-bundle-output <file>  Output path for the bundle \(default: frensense-corpus.frc\)"\);\n>>>>>>> origin/main',
    r'    println!("  --build-bundle-output <file>  Output path for the bundle (default: frensense-corpus.frc)");',
    content
)

with open("src/cli/commands.rs", "w") as f:
    f.write(content)
