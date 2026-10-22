#!/usr/bin/env python3
"""Generate figures for ISSRE paper"""
import json
import matplotlib.pyplot as plt
import matplotlib
import numpy as np

matplotlib.rcParams['font.family'] = 'serif'
matplotlib.rcParams['font.size'] = 13

OUTPUT_DIR = "papers/latex_projects/Attacking_Python_Vulnerabilities_with_an_AI_Agent/images"
ISSRE_DIR = "papers/latex_projects/_2026___ISSRE__Frédéric___Attacking_with_AI_Agents/images"

# Load results
with open("backups/combined_results.json") as f:
    results = json.load(f)

models = list(results.keys())
colors = ['#4285F4', '#34A853', '#EA4335', '#FBBC04']  # blue, green, red, yellow
n_models = len(models)

# ── Figure 1: Overall success rate bar chart ──────────────────────────────
fig, ax = plt.subplots(figsize=(6, 3))
rates = [results[m]['rate'] for m in models]

bars = ax.bar(models, rates, color=colors[:n_models], width=0.6, edgecolor='black', linewidth=0.5)
ax.set_ylabel('Exploitation Success Rate (%)')
ax.set_ylim(0, max(rates) + 10)
ax.grid(axis='y', alpha=0.3)

for bar, rate in zip(bars, rates):
    ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1,
            f'{rate:.0f}%', ha='center', va='bottom', fontweight='bold')

plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_overall_success.pdf", bbox_inches='tight')
plt.savefig(f"{OUTPUT_DIR}/fig_overall_success.png", bbox_inches='tight', dpi=150)
print("Saved: fig_overall_success")

# ── Figure 2: Success rate by CWE (grouped bar chart) ────────────────────
cwes = sorted(set(cwe for m in results.values() for cwe in m['cwe'].keys()))
cwe_labels = [c.replace('CWE-', '') for c in cwes]

fig, ax = plt.subplots(figsize=(9, 4))
x = np.arange(len(cwes))
width = 0.8 / n_models

for i, (model, color) in enumerate(zip(models, colors)):
    rates_cwe = []
    for cwe in cwes:
        data = results[model]['cwe'].get(cwe, {'pass': 0, 'fail': 0})
        total = data['pass'] + data['fail']
        rates_cwe.append(data['pass'] / total * 100 if total > 0 else 0)
    ax.bar(x + i*width, rates_cwe, width, label=model, color=color,
           edgecolor='black', linewidth=0.3)

ax.set_xlabel('CWE Type')
ax.set_ylabel('Success Rate (%)')
ax.set_xticks(x + width * (n_models - 1) / 2)
ax.set_xticklabels(cwe_labels, rotation=45, ha='right')
ax.set_ylim(0, 100)
ax.legend(loc='upper right', fontsize=10)
ax.grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_cwe_breakdown.pdf", bbox_inches='tight')
plt.savefig(f"{OUTPUT_DIR}/fig_cwe_breakdown.png", bbox_inches='tight', dpi=150)
print("Saved: fig_cwe_breakdown")

# ── Figure 3: Self-correction impact (iteration distribution) ────────────
fig, ax = plt.subplots(figsize=(6, 3.5))

for model, color in zip(models, colors):
    iters = results[model]['iterations']
    total_passed = results[model]['passed']
    if total_passed == 0:
        continue
    max_iter = 5
    cumulative = []
    running = 0
    # Combine iteration "0" (gold standard) and "1" (first LLM attempt) as "Iteration 1"
    running += iters.get("0", 0) + iters.get("1", 0)
    cumulative.append(running)
    for it in range(2, max_iter + 1):
        running += iters.get(str(it), 0)
        cumulative.append(running)
    ax.plot(range(1, max_iter+1), cumulative, marker='o', color=color,
            label=f'{model} ({total_passed}/100)', linewidth=2)

ax.set_xlabel('Iteration (plan-and-execute cycle)')
ax.set_ylabel('Cumulative Passed Files (out of 100)')
ax.set_xticks(range(1, 6))
ax.set_xticklabels(['1', '2', '3', '4', '5'])
ax.set_ylim(0, max(r['passed'] for r in results.values()) + 5)
ax.legend(fontsize=7)
ax.grid(alpha=0.3)

plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_self_correction.pdf", bbox_inches='tight')
plt.savefig(f"{OUTPUT_DIR}/fig_self_correction.png", bbox_inches='tight', dpi=150)
plt.savefig(f"{ISSRE_DIR}/fig_self_correction.png", bbox_inches='tight', dpi=150)
print("Saved: fig_self_correction")

print("\nAll figures generated.")
