#!/usr/bin/env python3
import json, os, subprocess, sys
from collections import defaultdict

FRENSENSE_BIN = os.environ.get("FRENSENSE_BIN", "./target/release/frensense")
NODEGOAT_DIR = os.environ.get("NODEGOAT_DIR", "/home/oxisrael/Friehub/Taas/benchmarks/NodeGoat")
GROUND_TRUTH_FILE = "scripts/nodegoat-ground-truth.json"

if not os.path.isdir(NODEGOAT_DIR):
    print(f"[ERROR] NodeGoat dir not found: {NODEGOAT_DIR}")
    sys.exit(1)

with open(GROUND_TRUTH_FILE) as f:
    gt_data = json.load(f)

# Group ground truth by filename
gt_by_file = defaultdict(list)
for item in gt_data:
    fname = item["file"].rsplit("/", 1)[-1]
    gt_by_file[fname].append(item)

print(f"[INFO] Ground truth: {len(gt_data)} vulnerabilities across {len(gt_by_file)} files")
print(f"[INFO] Scanning NodeGoat directory: {NODEGOAT_DIR}")

result = subprocess.run(
    [FRENSENSE_BIN, NODEGOAT_DIR, "--use-compiler", "--threshold", "0.0", "--min-confidence", "0.0", "--json"],
    capture_output=True,
    text=True,
    timeout=600
)

if result.returncode not in (0, 1):
    print(f"[WARN] frensense exited with code {result.returncode}", file=sys.stderr)

try:
    data = json.loads(result.stdout)
except json.JSONDecodeError as e:
    print(f"[ERROR] Could not parse frensense output: {e}")
    sys.exit(1)

advisories = data.get("advisories", [])
print(f"[INFO] Total advisories emitted: {len(advisories)}")

pattern_stats = defaultdict(lambda: {"TP": 0, "FP": 0})
total_tp = 0
total_fp = 0

found_gt_items = set()

for adv in advisories:
    rule_id = adv.get("rule_id", "UNKNOWN")
    af = adv.get("file_path", "").rsplit("/", 1)[-1]
    line = adv.get("line", 0)
    
    is_tp = False
    if af in gt_by_file:
        for g in gt_by_file[af]:
            if -5 <= (g["line"] - line) <= 75:
                is_tp = True
                found_gt_items.add(g["id"])
                break
                
    if is_tp:
        pattern_stats[rule_id]["TP"] += 1
        total_tp += 1
    else:
        pattern_stats[rule_id]["FP"] += 1
        total_fp += 1

recall = len(found_gt_items) / len(gt_data) if gt_data else 0

print("\n=== FRENSENSE NODEGOAT BENCHMARK ===")
print(f"Ground truth:      {len(gt_data)} vulnerabilities")
print(f"True Positives:    {total_tp}  (findings on known-vuln lines)")
print(f"False Positives:   {total_fp}  (findings on clean lines)")
precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
print(f"Precision:         {precision:.2%}")
print(f"Recall:            {recall:.2%}  ({len(found_gt_items)}/{len(gt_data)} vulnerabilities hit)")

print("\n--- Missed Vulnerabilities ---")
all_gt_ids = {g["id"] for g in gt_data}
missed_ids = all_gt_ids - found_gt_items
for i in sorted(missed_ids):
    for g in gt_data:
        if g["id"] == i:
            print(f" - {i}: {g['file']}:{g['line']}")
            break

print(f"\n{'PATTERN':<52} | {'TP':>4} | {'FP':>4} | {'PREC':>7}")
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

