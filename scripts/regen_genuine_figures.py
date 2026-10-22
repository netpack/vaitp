#!/usr/bin/env python3
"""Regenerate the ISSRE paper figures from the genuine-dataset full runs.

Reads the four latest full_*.json result files and produces:
  - fig_cwe_breakdown.png  (per-CWE success rate, grouped by model)
  - fig_self_correction.png (cumulative passes by self-correction iteration)
directly into the ISSRE paper images directory.
"""
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

matplotlib.rcParams["font.family"] = "serif"
matplotlib.rcParams["font.size"] = 13

ISSRE_DIR = ("papers/latex_projects/"
             "_2026___ISSRE__Frédéric___Attacking_with_AI_Agents/images")

# (label, path, color) in display order
RUNS = [
    ("Gemini 3.1 Pro", "ablation_results/full_gemini_3.1_pro_preview_20260629_000343.json", "#4285F4"),
    ("Grok 4.20",       "ablation_results/full_grok_4.20_reasoning_20260629_062205.json",     "#34A853"),
    ("Qwen3-235B",      "ablation_results/full_qwen3_235b_a22b_instruct_2507_maas_20260629_152331.json", "#EA4335"),
    ("DeepSeek R1-0528","ablation_results/full_deepseek_r1_0528_maas_20260629_115316.json",   "#FBBC04"),
]
# Ordered left-to-right by decreasing effect observability:
# natural (78,94,502) -> hook-observable (22,89,79,287) -> harness-limited (352,601,918)
CWE_ORDER = ["cwe78", "cwe94", "cwe502", "cwe22", "cwe89", "cwe79", "cwe287",
             "cwe352", "cwe601", "cwe918"]
CWE_LABELS = ["78", "94", "502", "22", "89", "79", "287", "352", "601", "918"]


def cwe_of(name):
    return name.split("_", 1)[0].lower()


def load(path):
    d = json.load(open(path))
    if "tests" not in d:  # summary_ style wrapper
        d = list(d.values())[0]
    return d


data = [(label, load(path), color) for label, path, color in RUNS]

# ---- Figure: per-CWE grouped bar chart ----
fig, ax = plt.subplots(figsize=(9, 4))
x = np.arange(len(CWE_ORDER))
n = len(data)
width = 0.8 / n
for i, (label, d, color) in enumerate(data):
    per = {c: [0, 0] for c in CWE_ORDER}
    for name, info in d["tests"].items():
        c = cwe_of(name)
        if c in per:
            per[c][1] += 1
            if info.get("passed"):
                per[c][0] += 1
    rates = [100.0 * per[c][0] / per[c][1] if per[c][1] else 0 for c in CWE_ORDER]
    ax.bar(x + i * width, rates, width, label=label, color=color,
           edgecolor="black", linewidth=0.3)

# Shade the three network classes (CWE-352/601/918) whose exploitation effect the
# harness cannot reliably observe; all models score ~0 there for that reason.
ax.axvspan(6.8, len(CWE_ORDER) - 0.15, color="0.92", zorder=0)
ax.text(8.3, 90, "effect not\nobservable", ha="center", va="top",
        fontsize=8, color="0.45", style="italic")

ax.set_xlabel("CWE Type")
ax.set_ylabel("Success Rate (%)")
ax.set_xticks(x + width * (n - 1) / 2)
ax.set_xticklabels(CWE_LABELS, rotation=45, ha="right")
ax.set_ylim(0, 100)
ax.legend(loc="upper right", fontsize=10)
ax.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(f"{ISSRE_DIR}/fig_cwe_breakdown.png", bbox_inches="tight", dpi=150)
print("Saved fig_cwe_breakdown.png")

# ---- Figure: self-correction cumulative passes by iteration ----
fig, ax = plt.subplots(figsize=(6, 3.5))
max_iter = 5
for label, d, color in data:
    iters = {}
    for info in d["tests"].values():
        if info.get("passed"):
            it = info.get("iteration", 1) or 1
            iters[it] = iters.get(it, 0) + 1
    total_passed = sum(iters.values())
    cumulative = []
    running = 0
    for it in range(1, max_iter + 1):
        running += iters.get(it, 0)
        cumulative.append(running)
    ax.plot(range(1, max_iter + 1), cumulative, marker="o", color=color,
            label=f"{label} ({total_passed}/100)", linewidth=2)

ax.set_xlabel("Iteration (plan-and-execute cycle)")
ax.set_ylabel("Cumulative Passed Files (out of 100)")
ax.set_xticks(range(1, 6))
ax.set_ylim(0, max(sum(1 for t in d["tests"].values() if t.get("passed")) for _, d, _ in data) + 6)
ax.legend(fontsize=8)
ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(f"{ISSRE_DIR}/fig_self_correction.png", bbox_inches="tight", dpi=150)
print("Saved fig_self_correction.png")
print("Done.")
