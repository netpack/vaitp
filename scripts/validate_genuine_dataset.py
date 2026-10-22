#!/usr/bin/env python3
"""
Validate the genuine Phase 3 dataset against the effect-based detectors.

For every sample, instrument BOTH the vulnerable and safe versions with the same
effect-based detector (symmetric), then check the four double-check conditions:

  C1  vuln + benign   -> runs cleanly (no crash), marker NOT created
  C2  vuln + malicious -> marker CREATED (genuine exploitation effect)
  C3  safe + benign   -> runs cleanly (no crash), marker NOT created
  C4  safe + malicious -> marker NOT created (patch blocks)

A sample is VALID iff all four hold. This is exactly the rigorous verdict the
framework will compute, so a sample passing here is a genuine, fair exploitation
target.

  stdio  : executed via subprocess (any python3).
  network: executed in-process via Flask's test_client (requires Flask -> run
           this with the project venv:  venv/bin/python scripts/validate_genuine_dataset.py).
           If Flask is unavailable, network samples are reported as SKIPPED.

Usage:
  venv/bin/python scripts/validate_genuine_dataset.py
"""
import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from urllib.parse import parse_qsl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(ROOT, "vaitp_dataset", "phase3_genuine")
VULN_DIR = os.path.join(DATASET, "vulnerable")
PATCH_DIR = os.path.join(DATASET, "injectable")
MANIFEST = os.path.join(DATASET, "manifest.json")

# Load the effect-based injector standalone (avoids the heavy orchestration import).
_spec = importlib.util.spec_from_file_location(
    "sei_standalone", os.path.join(ROOT, "orchestration", "side_effect_injector.py"))
_sei = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_sei)
inject_side_effect = _sei.inject_side_effect


def _instrument(code, success_file, strategy, category):
    return inject_side_effect(code, success_file, strategy, category)


# ---------------------------------------------------------------- stdio
def run_stdio(code, success_file, payload):
    """Run instrumented stdio code with payload on stdin. Returns (output, marker_created)."""
    d = tempfile.mkdtemp()
    marker = os.path.join(d, os.path.basename(success_file))
    code = code.replace(success_file, marker)
    # Natural-exploit payloads embed the literal success_file path (e.g.
    # "; touch /tmp/pwned"). Rewrite it to the per-run marker so the created
    # file is detected here and runs don't collide.
    payload = payload.replace(success_file, marker)
    script = os.path.join(d, "prog.py")
    with open(script, "w") as f:
        f.write(code)
    try:
        r = subprocess.run([sys.executable, script], input=payload, text=True,
                           capture_output=True, timeout=20, cwd=d)
        out = (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        out = "LAUNCH-ERROR: %s" % e
    return out, os.path.exists(marker)


def clean_run(out):
    """True if the program ran without an unhandled error/crash."""
    return ("ERROR:" not in out) and ("Traceback (most recent call last)" not in out) \
        and ("LAUNCH-ERROR" not in out)


# ---------------------------------------------------------------- network
def net_check_one(name, category):
    """Do the 4 network checks for one sample (call in a FRESH process to avoid
    global monkeypatch pollution). Returns (valid, detail)."""
    man = {e["name"]: e for e in json.load(open(MANIFEST))}
    e = man[name]
    vcode = open(os.path.join(VULN_DIR, name)).read()
    pcode = open(os.path.join(PATCH_DIR, name)).read()
    route = e.get("route", "")
    sf = "/tmp/pwned"

    def check(code, payload_qs, tag):
        d = tempfile.mkdtemp()
        marker = os.path.join(d, "pwned_" + tag)
        inst = inject_side_effect(code, sf, "network", category).replace(sf, marker)
        g = {"__name__": "x"}
        try:
            exec(compile(inst, "<a>", "exec"), g, g)
        except Exception as ex:
            return 0, False
        app = g.get("app")
        if app is None:
            return 0, False
        c = app.test_client()
        params = dict(parse_qsl(payload_qs, keep_blank_values=True))
        try:
            r = c.post("/" + route, json=params)
            return r.status_code, os.path.exists(marker)
        except Exception:
            return 0, False

    sv, mvb = check(vcode, e["benign"], "vb")
    _, mve = check(vcode, e["exploit"], "ve")
    sp, mpb = check(pcode, e["benign"], "pb")
    _, mpe = check(pcode, e["exploit"], "pe")
    c1 = (200 <= sv < 400) and not mvb
    c2 = mve
    c3 = (200 <= sp < 400) and not mpb
    c4 = not mpe
    valid = c1 and c2 and c3 and c4
    detail = "C1=%s C2=%s C3=%s C4=%s (status v_b=%s p_b=%s)" % (c1, c2, c3, c4, sv, sp)
    return valid, detail


# CWE -> category, matching the orchestrator's authoritative map.
_NET_CAT = {"cwe79": "xss", "cwe918": "ssrf", "cwe601": "open_redirect",
            "cwe352": "csrf", "cwe287": "auth"}


def validate_network(entry, vcode, pcode):
    """Run the per-sample network check in a FRESH subprocess (isolation)."""
    name = entry["name"]
    category = _NET_CAT.get(entry["cwe"], "flask_network")
    r = subprocess.run([sys.executable, os.path.abspath(__file__),
                        "--net-one", name, category],
                       capture_output=True, text=True, timeout=90)
    out = (r.stdout or "").strip()
    line = [l for l in out.splitlines() if l.startswith("NETRESULT ")]
    if not line:
        return False, "subprocess error: %s" % ((r.stderr or out)[:160])
    payload = json.loads(line[-1][len("NETRESULT "):])
    return payload["valid"], payload["detail"]


def _mk(base, sub):
    p = os.path.join(base, sub)
    os.makedirs(p, exist_ok=True)
    return p


def validate_stdio(entry, vcode, pcode):
    sf = "/tmp/pwned"
    cat_map = {"cwe89": "sqli", "cwe78": "command_injection", "cwe22": "path_traversal",
               "cwe502": "deserialization", "cwe94": "eval"}
    category = cat_map.get(entry["cwe"], "generic")
    vci = _instrument(vcode, sf, "stdio", category)
    pci = _instrument(pcode, sf, "stdio", category)

    out_vb, m_vb = run_stdio(vci, sf, entry["benign"])
    _, m_ve = run_stdio(vci, sf, entry["exploit"])
    out_pb, m_pb = run_stdio(pci, sf, entry["benign"])
    _, m_pe = run_stdio(pci, sf, entry["exploit"])

    c1 = clean_run(out_vb) and not m_vb
    c2 = m_ve
    c3 = clean_run(out_pb) and not m_pb
    c4 = not m_pe
    valid = c1 and c2 and c3 and c4
    detail = "C1(benign_vuln_clean)=%s C2(exploit_fires)=%s C3(benign_safe_clean)=%s C4(patch_blocks)=%s" % (
        c1, c2, c3, c4)
    if not c1:
        detail += " | vuln_benign_out=%r" % out_vb[:80]
    if not c3:
        detail += " | safe_benign_out=%r" % out_pb[:80]
    return valid, detail


def main():
    manifest = json.load(open(MANIFEST))
    have_flask = importlib.util.find_spec("flask") is not None

    results = []
    from collections import Counter, defaultdict
    by_cwe = defaultdict(lambda: Counter())

    for entry in manifest:
        name = entry["name"]
        with open(os.path.join(VULN_DIR, name)) as f:
            vcode = f.read()
        with open(os.path.join(PATCH_DIR, name)) as f:
            pcode = f.read()
        if entry["strategy"] == "stdio":
            valid, detail = validate_stdio(entry, vcode, pcode)
            status = "VALID" if valid else "INVALID"
        else:
            if not have_flask:
                status, detail = "SKIPPED(no-flask)", "run with venv python"
            else:
                valid, detail = validate_network(entry, vcode, pcode)
                status = "VALID" if valid else "INVALID"
        results.append({"name": name, "cwe": entry["cwe"], "status": status, "detail": detail})
        by_cwe[entry["cwe"]][status.split("(")[0]] += 1
        if status.startswith("INVALID"):
            print("  INVALID %-40s %s" % (name, detail))

    print("\n" + "=" * 72)
    print("  GENUINE DATASET VALIDATION")
    print("=" * 72)
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        print("  %-8s VALID=%d INVALID=%d SKIPPED=%d"
              % (cwe, c.get("VALID", 0), c.get("INVALID", 0), c.get("SKIPPED", 0)))
    total_valid = sum(1 for r in results if r["status"] == "VALID")
    total_invalid = sum(1 for r in results if r["status"].startswith("INVALID"))
    total_skip = sum(1 for r in results if r["status"].startswith("SKIPPED"))
    print("-" * 72)
    print("  TOTAL: VALID=%d INVALID=%d SKIPPED=%d (of %d)"
          % (total_valid, total_invalid, total_skip, len(results)))
    if not have_flask:
        print("\n  NOTE: Flask not found -> network samples skipped. Re-run with:")
        print("        venv/bin/python scripts/validate_genuine_dataset.py")

    with open(os.path.join("ablation_results", "genuine_validation.json"), "w") as f:
        json.dump(results, f, indent=2)
    print("\n  Saved -> ablation_results/genuine_validation.json")
    return 0 if total_invalid == 0 else 1


if __name__ == "__main__":
    os.makedirs("ablation_results", exist_ok=True)
    if len(sys.argv) >= 4 and sys.argv[1] == "--net-one":
        _valid, _detail = net_check_one(sys.argv[2], sys.argv[3])
        print("NETRESULT " + json.dumps({"valid": _valid, "detail": _detail}))
        sys.exit(0)
    sys.exit(main())
