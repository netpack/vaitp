#!/usr/bin/env python3
"""
Dataset validity triage for VAITP Phase 3.

Classifies every vulnerable/safe pair as GENUINE / BROKEN / UNCERTAIN based on:
  - Static signals: syntax validity, presence of no-op stubs, undefined names,
    and whether a real vulnerable sink is reachable.
  - Dynamic signals (stdio CWEs only, runnable with plain python3): does the
    program execute a benign input WITHOUT raising an unhandled exception?

A sample is only a valid exploitation target if (a) it runs on benign input
without crashing and (b) it contains a reachable vulnerable sink. Files that
crash on benign input or whose sink is stubbed out are not exploitable — they
can only produce false positives under input/reachability-based detection.

stdio CWEs : 89, 78, 22, 502, 94  (run here with python3)
network CWEs: 79, 918, 601, 352, 287 (static-only here; need Flask/Docker)

Usage:  python scripts/triage_dataset.py [--json triage.json]
"""
import argparse
import ast
import builtins
import json
import os
import subprocess
import sys

DATASET = "vaitp_dataset/phase3_sven_pyvul"
VULN_DIR = os.path.join(DATASET, "vulnerable")
PATCH_DIR = os.path.join(DATASET, "injectable")

STDIO_CWES = {"cwe89", "cwe78", "cwe22", "cwe502", "cwe94"}
NETWORK_CWES = {"cwe79", "cwe918", "cwe601", "cwe352", "cwe287"}

STUB_MARKERS = [
    "Auto-generated stubs",
    "Stubs for missing dependencies",
    "lambda *a, **kw: None",
    "def __getattr__(self, n): return",
    "--- End stubs ---",
]

BUILTIN_NAMES = set(dir(builtins)) | {
    "self", "cls", "__name__", "__file__", "__doc__",
    "Optional", "List", "Dict", "Tuple", "Any", "Union", "Set", "Type",
    "Callable", "Iterator", "Iterable", "Mapping", "Sequence",
}

# Sink signatures that indicate a real vulnerable operation is present in code.
SINK_SIGNATURES = {
    "cwe89": ["execute(", "executescript(", "executemany(", ".raw("],
    "cwe78": ["os.system", "os.popen", "subprocess.", "shell=True", "popen("],
    "cwe22": ["open(", "send_file", "send_from_directory", "extractall", "os.path.join"],
    "cwe502": ["pickle.load", "yaml.load", "yaml.unsafe_load", "marshal.load", "__reduce__"],
    "cwe94": ["eval(", "exec(", "compile(", "__import__"],
    "cwe79": ["render_template_string", "make_response", "return render", "Markup", "|safe", "f\"", "f'"],
    "cwe918": ["requests.get", "requests.post", "urlopen", "urllib", "httpx", ".get("],
    "cwe601": ["redirect(", "Location", "url_for"],
    "cwe352": ["@app.route", "request.form", "request.values", "session"],
    "cwe287": ["==", "compare", "match", "verify", "decode(", "authenticate", "login"],
}


def extract_cwe(name):
    return name.split("_", 1)[0].lower()


def has_stub(code):
    return any(m in code for m in STUB_MARKERS)


def count_undefined(code):
    """Count names used but never defined/imported (excludes builtins)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return -1, []
    used, defined, imported = set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            (used if isinstance(node.ctx, ast.Load) else defined).add(node.id)
        elif isinstance(node, ast.arg):
            defined.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                imported.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                imported.add(a.asname or a.name)
        elif isinstance(node, ast.Global) or isinstance(node, ast.Nonlocal):
            for n in node.names:
                defined.add(n)
    undefined = sorted(n for n in used if n not in defined and n not in imported
                       and n not in BUILTIN_NAMES)
    return len(undefined), undefined


def has_sink(code, cwe):
    sigs = SINK_SIGNATURES.get(cwe, [])
    return any(s in code for s in sigs)


# Benign inputs for stdio dynamic runs (per CWE convention from the scaffolds).
BENIGN_STDIO = {
    "cwe89": "alice",
    "cwe78": "main_vuln.py",
    "cwe22": "test.txt",
    "cwe502": "gASVEAAAAAAAAAB9lIwDa2V5lIwDdmFslHMu",  # base64 of a benign pickled dict
    "cwe94": "1 + 1",
}


def run_benign_stdio(path, cwe, timeout=15):
    """Run a stdio program on benign input; return (ran_ok, detail)."""
    benign = BENIGN_STDIO.get(cwe, "test")
    try:
        r = subprocess.run([sys.executable, path], input=benign, text=True,
                           capture_output=True, timeout=timeout,
                           cwd=os.path.dirname(path) or ".")
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, "launch-error: %s" % e
    out = (r.stdout or "") + (r.stderr or "")
    # The scaffolds wrap the call in try/except printing "ERROR: ...". Treat an
    # ERROR line or a Traceback or NameError as a crash on benign input.
    low = out
    if "Traceback (most recent call last)" in low:
        return False, "traceback"
    if "ERROR:" in low:
        # Extract the error briefly
        line = next((l for l in low.splitlines() if "ERROR:" in l), "ERROR")
        return False, line.strip()[:120]
    if r.returncode != 0:
        return False, "exit=%d" % r.returncode
    return True, "ok"


def classify(name):
    vuln_path = os.path.join(VULN_DIR, name)
    patch_path = os.path.join(PATCH_DIR, name)
    cwe = extract_cwe(name)
    with open(vuln_path) as f:
        vcode = f.read()
    pcode = ""
    if os.path.exists(patch_path):
        with open(patch_path) as f:
            pcode = f.read()

    rec = {"name": name, "cwe": cwe, "strategy": "stdio" if cwe in STDIO_CWES else "network"}
    rec["vuln_stub"] = has_stub(vcode)
    rec["patch_stub"] = has_stub(pcode)
    v_undef_n, v_undef = count_undefined(vcode)
    rec["vuln_undefined_n"] = v_undef_n
    rec["vuln_undefined"] = v_undef[:8]
    rec["vuln_has_sink"] = has_sink(vcode, cwe)
    rec["syntax_ok"] = v_undef_n != -1
    rec["has_patch"] = os.path.exists(patch_path)

    if rec["strategy"] == "stdio":
        ran_ok, detail = run_benign_stdio(vuln_path, cwe)
        rec["benign_ran"] = ran_ok
        rec["benign_detail"] = detail
    else:
        rec["benign_ran"] = None  # needs Flask/Docker
        rec["benign_detail"] = "network (not run here)"

    # Verdict
    reasons = []
    if not rec["syntax_ok"]:
        reasons.append("syntax-error")
    if rec["vuln_stub"]:
        reasons.append("has-stub")
    if v_undef_n > 0:
        reasons.append("undefined-names(%d)" % v_undef_n)
    if not rec["vuln_has_sink"]:
        reasons.append("no-sink")
    if rec["benign_ran"] is False:
        reasons.append("benign-crash")

    if rec["strategy"] == "stdio":
        if rec["benign_ran"] and rec["vuln_has_sink"] and not rec["vuln_stub"]:
            verdict = "GENUINE"
        elif rec["benign_ran"] is False or not rec["vuln_has_sink"] or not rec["syntax_ok"]:
            verdict = "BROKEN"
        else:
            verdict = "UNCERTAIN"
    else:
        # network: static only
        if rec["vuln_stub"] or v_undef_n > 0 or not rec["vuln_has_sink"] or not rec["syntax_ok"]:
            verdict = "BROKEN"
        else:
            verdict = "UNCERTAIN"  # needs dynamic confirmation
    rec["verdict"] = verdict
    rec["reasons"] = reasons
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="ablation_results/triage.json")
    args = ap.parse_args()

    names = sorted(f for f in os.listdir(VULN_DIR) if f.endswith(".py"))
    records = [classify(n) for n in names]

    # Summary
    from collections import Counter, defaultdict
    by_verdict = Counter(r["verdict"] for r in records)
    by_cwe = defaultdict(lambda: Counter())
    for r in records:
        by_cwe[r["cwe"]][r["verdict"]] += 1

    print("=" * 72)
    print("  DATASET VALIDITY TRIAGE")
    print("=" * 72)
    print("Total files: %d" % len(records))
    for v in ("GENUINE", "UNCERTAIN", "BROKEN"):
        print("  %-10s %d" % (v, by_verdict.get(v, 0)))
    print("\nPer-CWE (G/U/B):")
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        strat = "stdio" if cwe in STDIO_CWES else "network"
        print("  %-8s %-8s  G=%d U=%d B=%d"
              % (cwe, strat, c.get("GENUINE", 0), c.get("UNCERTAIN", 0), c.get("BROKEN", 0)))

    print("\nBroken / crashing stdio files (benign input fails):")
    for r in records:
        if r["strategy"] == "stdio" and r["benign_ran"] is False:
            print("  %-44s %s" % (r["name"], r["benign_detail"]))

    print("\nFiles with no-op stubs:")
    stubbed = [r["name"] for r in records if r["vuln_stub"]]
    print("  %d files: %s%s" % (len(stubbed), ", ".join(stubbed[:12]),
                                " ..." if len(stubbed) > 12 else ""))

    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    with open(args.json, "w") as f:
        json.dump(records, f, indent=2)
    print("\nSaved per-file triage -> %s" % args.json)


if __name__ == "__main__":
    main()
