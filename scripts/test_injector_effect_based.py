#!/usr/bin/env python3
"""
Validation suite for the effect-based side-effect injector.

Confirms that each category's detector fires on the *exploitation effect* (on the
vulnerable code) and stays SILENT on the safe code and on benign input — i.e. the
detector is a true differential signal, not a sink-reachability / input detector.

Runs WITHOUT Docker and without the heavy orchestration import chain: it loads the
injector module standalone, executes instrumented stdio programs in a subprocess,
and exercises the generated Flask hook against a stubbed Flask runtime.

Usage:  python scripts/test_injector_effect_based.py
Exit code 0 = all checks passed.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import types

PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "orchestration", "side_effect_injector.py")
_spec = importlib.util.spec_from_file_location("sei_standalone", PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
inject_side_effect = _mod.inject_side_effect

_failures = []


def _check(name, vuln_fired, safe_fired, benign_fired=False):
    ok = vuln_fired and not safe_fired and not benign_fired
    print("%-10s vuln=%s safe=%s benign=%s -> %s"
          % (name, vuln_fired, safe_fired, benign_fired, "OK" if ok else "PROBLEM"))
    if not ok:
        _failures.append(name)


# ---------------------------------------------------------------- stdio cases
def _run_stdio(code, payload):
    d = tempfile.mkdtemp()
    marker = os.path.join(d, "pwned")
    code = code.replace("/tmp/pwned", marker)
    script = os.path.join(d, "prog.py")
    with open(script, "w") as f:
        f.write(code)
    try:
        subprocess.run([sys.executable, script], input=payload, text=True,
                       capture_output=True, timeout=20, cwd=d)
    except Exception:
        pass
    return os.path.exists(marker)


SQLI_VULN = (
    "import sqlite3, sys, os\n"
    "conn = sqlite3.connect(':memory:')\n"
    "conn.execute('CREATE TABLE t (n TEXT)')\n"
    "conn.execute(\"INSERT INTO t VALUES ('alice')\")\n"
    "def run(u):\n"
    "    cur = conn.cursor()\n"
    "    cur.execute(\"SELECT * FROM t WHERE n='\" + u + \"'\")\n"
    "    return cur.fetchall()\n"
    "if __name__ == '__main__':\n    print(run(input()))\n"
)
SQLI_SAFE = SQLI_VULN.replace(
    "    cur.execute(\"SELECT * FROM t WHERE n='\" + u + \"'\")\n",
    "    cur.execute('SELECT * FROM t WHERE n=?', (u,))\n",
)
PT_VULN = (
    "import os, sys\n"
    "BASE='/tmp/safe_dir'\n"
    "os.makedirs(BASE, exist_ok=True)\n"
    "def run(u):\n    return open(os.path.join(BASE, u)).read()\n"
    "if __name__ == '__main__':\n"
    "    try: print(run(input()))\n    except Exception as e: print('ERR', e)\n"
)
PT_SAFE = PT_VULN.replace(
    "def run(u):\n    return open(os.path.join(BASE, u)).read()\n",
    "def run(u):\n    return open(os.path.join(BASE, os.path.basename(u))).read()\n",
)


def stdio_tests():
    p = "' OR '1'='1"
    _check("SQLi",
           _run_stdio(inject_side_effect(SQLI_VULN, "/tmp/pwned", "stdio", "sqli"), p),
           _run_stdio(inject_side_effect(SQLI_SAFE, "/tmp/pwned", "stdio", "sqli"), p),
           _run_stdio(inject_side_effect(SQLI_VULN, "/tmp/pwned", "stdio", "sqli"), "alice"))
    p = "../../../../etc/passwd"
    _check("PathTrav",
           _run_stdio(inject_side_effect(PT_VULN, "/tmp/pwned", "stdio", "path_traversal"), p),
           _run_stdio(inject_side_effect(PT_SAFE, "/tmp/pwned", "stdio", "path_traversal"), p),
           _run_stdio(inject_side_effect(PT_VULN, "/tmp/pwned", "stdio", "path_traversal"), "x.txt"))


# -------------------------------------------------------------- network cases
class _Headers(dict):
    def get(self, k, d=None):
        for kk, vv in self.items():
            if kk.lower() == k.lower():
                return vv
        return d


class _Req:
    def __init__(self, qs="", body="", method="GET", values=None):
        self.query_string = qs.encode(); self._b = body
        self.method = method; self.values = values or {}
    def get_data(self, as_text=False):
        return self._b


class _G:  # noqa
    pass


class _Resp:
    def __init__(self, body="", status=200, location=None):
        self._b = body; self.status_code = status; self.headers = _Headers()
        if location is not None:
            self.headers["Location"] = location
    def get_data(self, as_text=False):
        return self._b


def _drive(category, qs, body, response, method="GET", values=None):
    sample = ("import os\nfrom flask import Flask, request, redirect, jsonify\n"
              "app = Flask(__name__)\n@app.route('/x')\ndef x():\n    return 'ok'\n")
    d = tempfile.mkdtemp(); marker = os.path.join(d, "pwned")
    code = inject_side_effect(sample, "/tmp/pwned", "network", category).replace("/tmp/pwned", marker)
    cap = {"before": None, "after": None}
    holder = {"request": None, "g": None}

    class _App:
        def __init__(self, *a, **k): pass
        def route(self, *a, **k):
            return lambda f: f
        def before_request(self, f): cap["before"] = f; return f
        def after_request(self, f): cap["after"] = f; return f

    class _ReqP:
        def __getattr__(self, n): return getattr(holder["request"], n)

    class _GP:
        def __getattr__(self, n): return getattr(holder["g"], n)
        def __setattr__(self, n, v): setattr(holder["g"], n, v)

    fake = types.ModuleType("flask")
    fake.Flask = _App; fake.request = _ReqP(); fake.g = _GP()
    fake.redirect = lambda *a, **k: None; fake.jsonify = lambda *a, **k: None
    saved = sys.modules.get("flask"); sys.modules["flask"] = fake
    try:
        g = {}
        exec(compile(code, "<inst>", "exec"), g, g)
    finally:
        if saved is not None:
            sys.modules["flask"] = saved
        else:
            sys.modules.pop("flask", None)
    holder["request"] = _Req(qs=qs, body=body, method=method, values=values)
    holder["g"] = _G()
    if cap["before"]:
        cap["before"]()
    if cap["after"]:
        cap["after"](response)
    return os.path.exists(marker)


def network_tests():
    xp = "<script>alert(1)</script>"
    _check("XSS",
           _drive("xss", "q=" + xp, "", _Resp(body="hi " + xp)),
           _drive("xss", "q=" + xp, "", _Resp(body="hi &lt;script&gt;alert(1)&lt;/script&gt;")),
           _drive("xss", "q=hello", "", _Resp(body="hello")))
    _check("Redirect",
           _drive("open_redirect", "url=http://evil.com/x", "", _Resp(status=302, location="http://evil.com/x")),
           _drive("open_redirect", "url=http://evil.com/x", "", _Resp(status=302, location="/dashboard")))
    _check("Auth",
           _drive("jwt", "token=forged", "", _Resp(body='{"authenticated": true}')),
           _drive("jwt", "token=forged", "", _Resp(body='{"authenticated": false}')))
    _check("CSRF",
           _drive("csrf", "", "data=x", _Resp(body="updated", status=200), method="POST", values={"data": "x"}),
           _drive("csrf", "", "data=x", _Resp(body="blocked", status=400), method="POST", values={"data": "x"}))


if __name__ == "__main__":
    print("=== stdio detectors ===")
    stdio_tests()
    print("=== network detectors ===")
    network_tests()
    print("=" * 40)
    if _failures:
        print("FAILED:", ", ".join(_failures))
        sys.exit(1)
    print("All effect-based detector checks passed.")
