#!/usr/bin/env python3
"""Generate the RQ3 figure (recovery vs first-attempt) in the ISSRE paper style.

Grouped bars per model: first-cycle (zero-shot) vs final (after self-correction),
annotated with the self-correction gain. Matches fig_cwe_breakdown / fig_self_correction:
serif font, per-model Google-brand colors, y-grid, dpi 150.

Data (Gemini best-performing; single run) from the paper's RQ2/RQ3 analysis:
    Gemini 35 -> 67 (+32),  Grok 42 -> 57 (+15),  Qwen 39 -> 45 (+6),  DeepSeek 32 -> 36 (+4)
Note the crossover: Grok has the best first attempt (42 > 35) yet Gemini wins overall.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import numpy as np

matplotlib.rcParams["font.family"] = "serif"
matplotlib.rcParams["font.size"] = 13

ISSRE_DIR = ("papers/latex_projects/"
             "_2026___ISSRE__Frédéric___Attacking_with_AI_Agents/images")

# (label, color, first-cycle, final) — same colors as the other two figures
MODELS = [
    ("Gemini 3.1 Pro",   "#4285F4", 35, 67),
    ("Grok 4.20",        "#34A853", 42, 57),
    ("Qwen3-235B",       "#EA4335", 39, 45),
    ("DeepSeek R1-0528", "#FBBC04", 32, 36),
]

x = np.arange(len(MODELS))
w = 0.38
fig, ax = plt.subplots(figsize=(6.2, 3.6))

for i, (label, color, first, final) in enumerate(MODELS):
    ax.bar(i - w / 2, first, w, color=color, alpha=0.40,
           edgecolor="black", linewidth=0.3)
    ax.bar(i + w / 2, final, w, color=color, alpha=1.0,
           edgecolor="black", linewidth=0.3)
    ax.text(i - w / 2, first + 1, str(first), ha="center", va="bottom", fontsize=9)
    ax.text(i + w / 2, final + 1, str(final), ha="center", va="bottom", fontsize=9)
    gain = final - first
    ax.annotate(f"+{gain}", xy=(i, max(first, final) + 5), ha="center",
                fontsize=11, color=color, fontweight="bold")

ax.set_xticks(x)
ax.set_xticklabels([m[0] for m in MODELS], rotation=18, ha="right", fontsize=10)
ax.set_ylabel("Successful exploitations (of 100)")
ax.set_ylim(0, 80)
ax.grid(axis="y", alpha=0.3)

legend = [
    Patch(facecolor="0.5", alpha=0.40, edgecolor="black", linewidth=0.3,
          label="First cycle (zero-shot)"),
    Patch(facecolor="0.5", alpha=1.0, edgecolor="black", linewidth=0.3,
          label="Final (after self-correction)"),
]
ax.legend(handles=legend, loc="upper right", fontsize=9)

plt.tight_layout()
out = f"{ISSRE_DIR}/fig_rq3_recovery.png"
plt.savefig(out, bbox_inches="tight", dpi=150)
print("Saved", out)
