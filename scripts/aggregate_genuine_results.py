#!/usr/bin/env python3
"""
Aggregate full-pipeline results on the genuine dataset into the tables the paper
needs: overall success per model, per-CWE breakdown, and evidence-level split
(natural vs hook-assisted). Reads ablation_results/full_*.json.

Usage:  python scripts/aggregate_genuine_results.py
"""
import glob
import json
import os
from collections import Counter, defaultdict

RESULTS_GLOB = "ablation_results/full_*.json"

# Display name mapping (model_name in the file -> paper label).
MODEL_LABELS = {
    "gemini-3.1-pro-preview": "Gemini 3.1 Pro",
    "gemini_3.1_pro_preview": "Gemini 3.1 Pro",
    "grok-4.20-reasoning": "Grok 4.20",
    "grok_4.20_reasoning": "Grok 4.20",
    "deepseek-r1-0528-maas": "DeepSeek R1-0528",
    "deepseek_r1_0528_maas": "DeepSeek R1-0528",
    "qwen3-235b-a22b-instruct-2507-maas": "Qwen3-235B",
    "qwen3_235b_a22b_instruct_2507_maas": "Qwen3-235B",
}

NATURAL_CWES = {"cwe78", "cwe94", "cwe22", "cwe502"}
HOOK_CWES = {"cwe89", "cwe79", "cwe918", "cwe601", "cwe352", "cwe287"}
CWE_ORDER = ["cwe22", "cwe78", "cwe89", "cwe94", "cwe502",
             "cwe79", "cwe287", "cwe352", "cwe601", "cwe918"]
CWE_PRETTY = {
    "cwe22": "CWE-22", "cwe78": "CWE-78", "cwe89": "CWE-89", "cwe94": "CWE-94",
    "cwe502": "CWE-502", "cwe79": "CWE-79", "cwe287": "CWE-287",
    "cwe352": "CWE-352", "cwe601": "CWE-601", "cwe918": "CWE-918",
}


def cwe_of(name):
    return name.split("_", 1)[0].lower()


def label_of(model):
    key = model.split("/")[-1]
    return MODEL_LABELS.get(key, key)


def load_latest_per_model():
    """If multiple full_*.json exist per model, keep the most recent."""
    by_model = {}
    for path in sorted(glob.glob(RESULTS_GLOB)):
        d = json.load(open(path))
        model = label_of(d.get("model", os.path.basename(path)))
        ts = d.get("timestamp", "")
        if model not in by_model or ts > by_model[model][0]:
            by_model[model] = (ts, d, path)
    return {m: (d, p) for m, (ts, d, p) in by_model.items()}


def main():
    runs = load_latest_per_model()
    if not runs:
        print("No full_*.json result files found in ablation_results/.")
        return

    order = ["Gemini 3.1 Pro", "Grok 4.20", "Qwen3-235B", "DeepSeek R1-0528"]
    models = [m for m in order if m in runs] + [m for m in runs if m not in order]

    # ---- Overall ----
    print("=" * 70)
    print("  OVERALL SUCCESS (genuine dataset, effect-based symmetric)")
    print("=" * 70)
    print("  %-20s %6s %6s %7s" % ("Model", "PASS", "TOTAL", "Rate"))
    overall = {}
    for m in models:
        d = runs[m][0]
        p, t = d.get("passed", 0), d.get("total", 0)
        overall[m] = (p, t)
        print("  %-20s %6d %6d %6.1f%%" % (m, p, t, (100.0 * p / t if t else 0)))

    # ---- Per-CWE ----
    percwe = {m: defaultdict(lambda: [0, 0]) for m in models}  # cwe -> [pass, total]
    evidence = {m: {"natural": [0, 0], "hook_assisted": [0, 0]} for m in models}
    for m in models:
        tests = runs[m][0].get("tests", {})
        for name, info in tests.items():
            cwe = cwe_of(name)
            passed = bool(info.get("passed"))
            percwe[m][cwe][1] += 1
            if passed:
                percwe[m][cwe][0] += 1
            lvl = "natural" if cwe in NATURAL_CWES else "hook_assisted"
            evidence[m][lvl][1] += 1
            if passed:
                evidence[m][lvl][0] += 1

    print("\n" + "=" * 70)
    print("  PER-CWE PASS RATE")
    print("=" * 70)
    header = "  %-9s" % "CWE" + "".join("%-16s" % m for m in models)
    print(header)
    for cwe in CWE_ORDER:
        row = "  %-9s" % CWE_PRETTY.get(cwe, cwe)
        for m in models:
            p, t = percwe[m][cwe]
            row += "%-16s" % ("%d/%d (%.0f%%)" % (p, t, (100.0 * p / t if t else 0)))
        print(row)

    print("\n" + "=" * 70)
    print("  EVIDENCE LEVEL (natural vs hook-assisted)")
    print("=" * 70)
    for m in models:
        n = evidence[m]["natural"]
        h = evidence[m]["hook_assisted"]
        print("  %-20s natural %d/%d (%.0f%%)   hook-assisted %d/%d (%.0f%%)" % (
            m, n[0], n[1], (100.0 * n[0] / n[1] if n[1] else 0),
            h[0], h[1], (100.0 * h[0] / h[1] if h[1] else 0)))

    # ---- LaTeX overall table ----
    print("\n% ---- LaTeX: overall results ----")
    print(r"\begin{tabular}{@{}lccc@{}}")
    print(r"\toprule")
    print(r"\textbf{Model} & \textbf{PASS} & \textbf{FAIL} & \textbf{Success (\%)} \\ \midrule")
    for m in models:
        p, t = overall[m]
        print(r"%s & %d & %d & %d\%% \\" % (m, p, t - p, round(100.0 * p / t if t else 0)))
    print(r"\bottomrule")
    print(r"\end{tabular}")

    missing = [m for m in order if m not in runs]
    if missing:
        print("\n  WARNING: no full-run results for: %s" % ", ".join(missing))


if __name__ == "__main__":
    main()
