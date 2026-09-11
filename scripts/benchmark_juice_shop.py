#!/usr/bin/env python3
"""
Frensense OWASP Juice Shop Benchmark
=====================================
Precision/Recall evaluation against the OWASP Juice Shop's
own ground truth (challengeUtils.solveIf calls mark vulnerable lines).

Usage:
    python3 scripts/benchmark_juice_shop.py [--juice-shop-dir PATH] [--frensense-bin PATH]
"""
import json
import os
import re
import sys
import subprocess
import tempfile
from collections import defaultdict

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
JUICE_SHOP_DIR = os.path.abspath(
    os.environ.get("JUICE_SHOP_DIR", "../juice-shop")
)
FRENSENSE_BIN = os.environ.get(
    "FRENSENSE_BIN", "./target/release/frensense"
)
SCAN_SUBDIRS = ["routes", "lib", "models"]

# ---------------------------------------------------------------------------
# 1. Build ground truth from Juice Shop challenge markers
# ---------------------------------------------------------------------------
solve_if_regex = re.compile(
    r'challengeUtils\.solveIf\(\s*challenges\.([a-zA-Z0-9_]+)'
)

vuln_files: set[str] = set()
vuln_map: dict[str, list[str]] = defaultdict(list)

for subdir in SCAN_SUBDIRS:
    abs_dir = os.path.join(JUICE_SHOP_DIR, subdir)
    if not os.path.isdir(abs_dir):
        print(f"[WARN] directory not found, skipping: {abs_dir}", file=sys.stderr)
        continue
    for root, _, files in os.walk(abs_dir):
        for fname in files:
            if fname.endswith((".ts", ".js")):
                path = os.path.join(root, fname)
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                matches = solve_if_regex.findall(content)
                if matches:
                    vuln_files.add(path)
                    vuln_map[path].extend(matches)

print(f"[INFO] Ground truth: {len(vuln_files)} vulnerable files, "
      f"{sum(len(v) for v in vuln_map.values())} challenges", file=sys.stderr)

if not vuln_files:
    print("[ERROR] No vulnerable files found. Check JUICE_SHOP_DIR.", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# 2. Run frensense on just the juice-shop scan dirs
# ---------------------------------------------------------------------------
scan_paths = [
    os.path.join(JUICE_SHOP_DIR, d)
    for d in SCAN_SUBDIRS
    if os.path.isdir(os.path.join(JUICE_SHOP_DIR, d))
]

if not scan_paths:
    print("[ERROR] No scan paths found under JUICE_SHOP_DIR.", file=sys.stderr)
    sys.exit(1)

print(f"[INFO] Scanning juice-shop directory: {JUICE_SHOP_DIR}", file=sys.stderr)

with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
    results_file = tf.name

try:
    result = subprocess.run(
        [FRENSENSE_BIN] + scan_paths + ["--use-compiler", "--json"],
        capture_output=True,
        text=True,
        timeout=600,
    )
    # frensense writes debug/progress to stderr, JSON to stdout
    raw_json = result.stdout
    if result.returncode not in (0, 1):  # 1 = --strict mode findings
        print(f"[WARN] frensense exited with code {result.returncode}", file=sys.stderr)

    with open(results_file, "w") as fh:
        fh.write(raw_json)

    data = json.loads(raw_json)
except subprocess.TimeoutExpired:
    print("[ERROR] frensense timed out.", file=sys.stderr)
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"[ERROR] Could not parse frensense output: {e}", file=sys.stderr)
    print(f"[DEBUG] Raw output (first 500 chars): {raw_json[:500]}", file=sys.stderr)
    sys.exit(1)
finally:
    os.unlink(results_file)

# ---------------------------------------------------------------------------
# 3. Classify advisories as TP or FP
# ---------------------------------------------------------------------------
advisories = data.get("advisories", [])
print(f"[INFO] Total advisories emitted: {len(advisories)}", file=sys.stderr)

pattern_stats: dict[str, dict] = defaultdict(lambda: {"TP": 0, "FP": 0})
total_tp = 0
total_fp = 0

# Filter for actual semantic vulnerability classes
STRICT_PREFIXES = ("CORPUS_TS_IDOR", "CORPUS_TS_SQLI", "CORPUS_TS_NOSQLI", "CORPUS_TS_CMDI", "CORPUS_TS_XSS", "CORPUS_TS_SSRF", "CORPUS_TS_PATH_TRAVERSAL")

for adv in advisories:
    file_path = adv.get("file_path", "")
    rule_id = adv.get("rule_id", "UNKNOWN")

    # Only evaluate high-signal semantic rules
    if not rule_id.startswith(STRICT_PREFIXES):
        continue

    if file_path in vuln_files:
        pattern_stats[rule_id]["TP"] += 1
        total_tp += 1
    else:
        pattern_stats[rule_id]["FP"] += 1
        total_fp += 1

# ---------------------------------------------------------------------------
# 4. Recall: how many vuln files did we catch at least one finding in?
# ---------------------------------------------------------------------------
found_vuln_files = {
    adv["file_path"] for adv in advisories if adv.get("file_path") in vuln_files
}
recall = len(found_vuln_files) / len(vuln_files) if vuln_files else 0

# ---------------------------------------------------------------------------
# 5. Output
# ---------------------------------------------------------------------------
print()
print("=== FRENSENSE OWASP JUICE SHOP BENCHMARK ===")
print(f"Ground truth:      {len(vuln_files)} vulnerable files")
print(f"True Positives:    {total_tp}  (findings on known-vuln files)")
print(f"False Positives:   {total_fp}  (findings on clean files)")
precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
print(f"Precision:         {precision:.2%}")
print(f"File Recall:       {recall:.2%}  ({len(found_vuln_files)}/{len(vuln_files)} vuln files hit)")

missed_files = vuln_files - found_vuln_files
if missed_files:
    print("\n--- Missed Vulnerable Files ---")
    for f in sorted(missed_files):
        print(f" - {f}")

print()

print(f"{'PATTERN':<52} | {'TP':>4} | {'FP':>4} | {'PREC':>7}")
print("-" * 77)

sorted_patterns = sorted(
    pattern_stats.items(), key=lambda x: x[1]["TP"], reverse=True
)

for pattern, stats in sorted_patterns:
    tp = stats["TP"]
    fp = stats["FP"]
    total = tp + fp
    prec = (tp / total) if total > 0 else 0.0
    print(f"{pattern:<52} | {tp:>4} | {fp:>4} | {prec:>6.2%}")
