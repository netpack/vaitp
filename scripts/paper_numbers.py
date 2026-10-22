#!/usr/bin/env python3
"""Compute every number the paper needs from the latest full_*.json runs."""
import glob, json, os
from collections import defaultdict, Counter

FILES = {
    "Gemini 3.1 Pro": "ablation_results/summary_gemini_3.1_pro_preview_20260629_000343.json",
    "Grok 4.20": "ablation_results/summary_grok_4.20_reasoning_20260629_062205.json",
    "Qwen3-235B": "ablation_results/summary_qwen3_235b_a22b_instruct_2507_maas_20260629_152331.json",
    "DeepSeek R1-0528": "ablation_results/summary_deepseek_r1_0528_maas_20260629_115316.json",
}
ORDER = ["Gemini 3.1 Pro", "Grok 4.20", "Qwen3-235B", "DeepSeek R1-0528"]
NATURAL = {"cwe78", "cwe94", "cwe22", "cwe502"}
CWE_ORDER = ["cwe22","cwe78","cwe89","cwe94","cwe502","cwe79","cwe287","cwe352","cwe601","cwe918"]

def cwe_of(n): return n.split("_",1)[0].lower()

def load(path):
    d = json.load(open(path))
    return d["full"]["tests"], d["full"]["passed"], d["full"]["total"]

data = {}
for m, f in FILES.items():
    tests, passed, total = load(f)
    data[m] = tests

print("="*78)
print("OVERALL + FIRST-CYCLE (iteration==1) + SELF-CORRECTION")
print("="*78)
print("%-18s %5s %6s %10s %12s" % ("Model","PASS","Rate","1st-cycle","via-selfcorr"))
for m in ORDER:
    tests = data[m]
    passed = sum(1 for t in tests.values() if t["passed"])
    first = sum(1 for t in tests.values() if t["passed"] and t.get("iteration")==1)
    print("%-18s %5d %5.0f%% %10d %12d" % (m, passed, passed, first, passed-first))

print("\n"+"="*78)
print("PER-CWE PASS (out of 10 each)")
print("="*78)
hdr = "%-9s" % "CWE" + "".join("%-14s" % m.split()[0] for m in ORDER)
print(hdr)
percwe = {m: defaultdict(lambda:[0,0]) for m in ORDER}
for m in ORDER:
    for n,t in data[m].items():
        c = cwe_of(n); percwe[m][c][1]+=1
        if t["passed"]: percwe[m][c][0]+=1
for c in CWE_ORDER:
    row = "%-9s" % c.upper().replace("CWE","CWE-")
    for m in ORDER:
        p,tt = percwe[m][c]; row += "%-14s" % ("%d/%d"%(p,tt))
    print(row)

print("\n"+"="*78)
print("EVIDENCE LEVEL")
print("="*78)
for m in ORDER:
    nat=[0,0]; hook=[0,0]
    for n,t in data[m].items():
        c=cwe_of(n)
        tgt = nat if c in NATURAL else hook
        tgt[1]+=1
        if t["passed"]: tgt[0]+=1
    print("%-18s natural %2d/%2d (%3.0f%%)   hook %2d/%2d (%3.0f%%)" % (
        m, nat[0],nat[1],100*nat[0]/nat[1], hook[0],hook[1],100*hook[0]/hook[1]))

print("\n"+"="*78)
print("ITERATION DISTRIBUTION (passed only)")
print("="*78)
for m in ORDER:
    dist = Counter(t["iteration"] for t in data[m].values() if t["passed"])
    print("%-18s %s" % (m, dict(sorted(dist.items()))))

print("\n"+"="*78)
print("FAILURE CATEGORIES")
print("="*78)
def categorize(reasons):
    r = " ".join(reasons)
    if "Planner failed" in r: return "Planner/JSON failure"
    if "Patch Bypassed" in r: return "Patch bypassed (incomplete patch)"
    if "Vuln Safe" in r: return "Exploit not triggered"
    if "Broken" in r: return "Infra/benign broken"
    if "Timeout" in r: return "Timeout"
    if "Exception" in r or "Error" in r: return "Infra/runtime error"
    return "Other: "+r[:40]
for m in ORDER:
    cats = Counter()
    for n,t in data[m].items():
        if not t["passed"]:
            cats[categorize(t["failure_reasons"])]+=1
    total_fail = sum(cats.values())
    print("\n%s  (%d failures)" % (m, total_fail))
    for k,v in cats.most_common():
        print("   %-40s %d" % (k, v))
