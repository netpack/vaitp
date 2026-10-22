#!/usr/bin/env python3
"""
Build Phase 3 experiment dataset from SVEN and PyVul.

Extracts 10 vulnerable/patched Python file pairs per CWE (100 total),
sourced across both datasets. Each file is scaffolded into a complete,
runnable Python program suitable for Phase 3 Docker-based exploitation.

Key: only selects functions that are self-contained enough to run in
isolation (≤3 undefined external names after scaffolding).

Output structure:
  vaitp_dataset/phase3_sven_pyvul/vulnerable/  — vulnerable code
  vaitp_dataset/phase3_sven_pyvul/injectable/  — patched (safe) code
"""

import ast
import builtins
import json
import os
import re
import textwrap
from collections import defaultdict

# ── Configuration ──────────────────────────────────────────────────────────
OUTPUT_BASE = "vaitp_dataset/phase3_sven_pyvul"
SVEN_TRAIN = "vaitp_dataset/sven/data_train_val/train"
PYVUL_FUNC = "vaitp_dataset/pyvul/dataset/function_level_dataset.out"
PYVUL_CWE_MAP = "vaitp_dataset/pyvul/dataset/commits_cwe_map.json"
FILES_PER_CWE = 10

TARGET_CWES = [
    ("CWE-89",  "SQL Injection"),
    ("CWE-78",  "OS Command Injection"),
    ("CWE-22",  "Path Traversal"),
    ("CWE-502", "Deserialization of Untrusted Data"),
    ("CWE-94",  "Code Injection"),
    ("CWE-79",  "Cross-Site Scripting (XSS)"),
    ("CWE-918", "Server-Side Request Forgery (SSRF)"),
    ("CWE-601", "Open Redirect"),
    ("CWE-352", "Cross-Site Request Forgery (CSRF)"),
    ("CWE-287", "Improper Authentication"),
]

SVEN_CWE_FILES = {
    "CWE-22": "cwe-022.jsonl", "CWE-78": "cwe-078.jsonl",
    "CWE-79": "cwe-079.jsonl", "CWE-89": "cwe-089.jsonl",
}

BUILTIN_NAMES = set(dir(builtins)) | {
    "Optional", "List", "Dict", "Tuple", "Any", "Union", "Set", "Type",
    "Callable", "Iterator", "Iterable", "Mapping", "Sequence",
}

# Names injected by our scaffold templates
SCAFFOLD_NAMES = {
    "app", "conn", "user_input", "raw", "url", "result", "e", "f",
    "__name__", "__main__", "BASE_DIR", "request", "session",
    "jsonify", "make_response", "redirect", "Flask",
}

# ── Scaffold templates ─────────────────────────────────────────────────────
SCAFFOLD = {
    "CWE-89": ("stdio", textwrap.dedent("""\
        import sqlite3
        import sys
        import os

        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')")
        conn.execute("INSERT INTO users VALUES (2, 'bob', 'bob@example.com')")
        conn.commit()

        {FUNC}

        if __name__ == "__main__":
            user_input = input()
            try:
                result = {CALL}
                print("RESULT:", result)
            except Exception as e:
                print("ERROR:", e)
    """)),
    "CWE-78": ("stdio", textwrap.dedent("""\
        import subprocess
        import os
        import sys

        {FUNC}

        if __name__ == "__main__":
            user_input = input()
            try:
                result = {CALL}
                print("RESULT:", result)
            except Exception as e:
                print("ERROR:", e)
    """)),
    "CWE-22": ("stdio", textwrap.dedent("""\
        import os
        import sys

        BASE_DIR = "/tmp/safe_dir"
        os.makedirs(BASE_DIR, exist_ok=True)
        with open(os.path.join(BASE_DIR, "test.txt"), "w") as f:
            f.write("safe content")

        {FUNC}

        if __name__ == "__main__":
            user_input = input()
            try:
                result = {CALL}
                print("RESULT:", result)
            except Exception as e:
                print("ERROR:", e)
    """)),
    "CWE-502": ("stdio", textwrap.dedent("""\
        import pickle
        import yaml
        import sys
        import os
        import base64

        {FUNC}

        if __name__ == "__main__":
            raw = sys.stdin.buffer.read()
            try:
                result = {CALL}
                print("RESULT:", result)
            except Exception as e:
                print("ERROR:", e)
    """)),
    "CWE-94": ("stdio", textwrap.dedent("""\
        import sys
        import os

        {FUNC}

        if __name__ == "__main__":
            user_input = input()
            try:
                result = {CALL}
                print("RESULT:", result)
            except Exception as e:
                print("ERROR:", e)
    """)),
    "CWE-79": ("network", textwrap.dedent("""\
        from flask import Flask, request, make_response
        import sys
        import os

        app = Flask(__name__)

        {FUNC}

        @app.route("/test")
        def test_endpoint():
            user_input = request.args.get("q", "")
            try:
                result = {CALL}
                return str(result)
            except Exception as e:
                return str(e), 500

        if __name__ == "__main__":
            app.run(host="0.0.0.0", port=5000)
    """)),
    "CWE-918": ("network", textwrap.dedent("""\
        from flask import Flask, request
        import requests as req_lib
        import urllib.request
        import sys
        import os

        app = Flask(__name__)

        {FUNC}

        @app.route("/fetch")
        def fetch_endpoint():
            url = request.args.get("url", "")
            try:
                result = {CALL}
                return str(result)
            except Exception as e:
                return str(e), 500

        if __name__ == "__main__":
            app.run(host="0.0.0.0", port=5000)
    """)),
    "CWE-601": ("network", textwrap.dedent("""\
        from flask import Flask, request, redirect
        import sys
        import os

        app = Flask(__name__)

        {FUNC}

        @app.route("/redirect")
        def redirect_endpoint():
            url = request.args.get("url", "")
            try:
                result = {CALL}
                return str(result)
            except Exception as e:
                return str(e), 500

        if __name__ == "__main__":
            app.run(host="0.0.0.0", port=5000)
    """)),
    "CWE-352": ("network", textwrap.dedent("""\
        from flask import Flask, request, session
        import sys
        import os

        app = Flask(__name__)
        app.secret_key = "test-secret-key"

        {FUNC}

        @app.route("/action", methods=["GET", "POST"])
        def action_endpoint():
            user_input = request.form.get("data", request.args.get("data", ""))
            try:
                result = {CALL}
                return str(result)
            except Exception as e:
                return str(e), 500

        if __name__ == "__main__":
            app.run(host="0.0.0.0", port=5000)
    """)),
    "CWE-287": ("network", textwrap.dedent("""\
        from flask import Flask, request, jsonify
        import sys
        import os

        app = Flask(__name__)

        {FUNC}

        @app.route("/auth", methods=["GET", "POST"])
        def auth_endpoint():
            user_input = request.args.get("token", request.form.get("token", ""))
            try:
                result = {CALL}
                return jsonify({{"authenticated": bool(result), "result": str(result)}})
            except Exception as e:
                return str(e), 500

        if __name__ == "__main__":
            app.run(host="0.0.0.0", port=5000)
    """)),
}


def safe_filename(cwe, dataset, index, func_name):
    clean = re.sub(r'[^a-zA-Z0-9_]', '_', func_name)[:30]
    return f"{cwe.lower().replace('-', '')}_{dataset}_{index:02d}_{clean}.py"


def dedent_code(code):
    lines = code.split('\n')
    non_empty = [l for l in lines if l.strip()]
    if not non_empty:
        return code
    min_indent = min(len(l) - len(l.lstrip()) for l in non_empty)
    return '\n'.join(l[min_indent:] if len(l) >= min_indent else l for l in lines)


def strip_self(code):
    """Remove self/cls from function signatures and self.xxx references."""
    # Remove self/cls from def line
    code = re.sub(r'def\s+(\w+)\s*\(\s*(?:self|cls)\s*,?\s*', r'def \1(', code)
    code = re.sub(r'def\s+(\w+)\s*\(\s*(?:self|cls)\s*\)', r'def \1()', code)
    # Replace self.method() -> method()
    code = re.sub(r'\bself\.(\w+)\s*\(', r'\1(', code)
    # Replace self.attr -> attr
    code = re.sub(r'\bself\.(\w+)', r'\1', code)
    return code


def get_func_info(code):
    """Extract function name and params from code."""
    match = re.search(r'def\s+(\w+)\s*\(([^)]*)\)', code)
    if not match:
        return None, []
    name = match.group(1)
    params_str = match.group(2)
    params = [p.strip().split('=')[0].split(':')[0].strip()
              for p in params_str.split(',') if p.strip()]
    return name, params


def build_call(func_name, params, cwe):
    """Build the function call string for the scaffold."""
    if not params:
        return f"{func_name}()"
    if len(params) == 1:
        if cwe == "CWE-502":
            return f"{func_name}(raw)"
        if cwe in ("CWE-918", "CWE-601"):
            return f"{func_name}(url)"
        return f"{func_name}(user_input)"
    if cwe == "CWE-89" and len(params) >= 2:
        rest = ', '.join(['user_input'] + ['None'] * (len(params) - 2))
        return f"{func_name}(conn, {rest})"
    args = ['user_input'] + ['None'] * (len(params) - 1)
    return f"{func_name}({', '.join(args)})"


def count_undefined(code):
    """Count undefined names in scaffolded code. Lower = more self-contained."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return 999

    used = set()
    defined = set()
    imported = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.FunctionDef):
            defined.add(node.name)
            for arg in node.args.args:
                defined.add(arg.arg)
            for default in node.args.defaults + node.args.kw_defaults:
                if isinstance(default, ast.Name):
                    used.add(default.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
            for alias in node.names:
                imported.add(alias.asname or alias.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    defined.add(t.id)
        elif isinstance(node, ast.For):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)
            elif isinstance(node.target, ast.Tuple):
                for elt in node.target.elts:
                    if isinstance(elt, ast.Name):
                        defined.add(elt.id)
        elif isinstance(node, ast.With):
            for item in node.items:
                if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                    defined.add(item.optional_vars.id)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                defined.add(node.name)
        elif isinstance(node, ast.comprehension):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)

    undefined = used - defined - imported - BUILTIN_NAMES - SCAFFOLD_NAMES
    return len(undefined)


def scaffold(func_code, func_name, params, cwe):
    """Build a complete runnable program."""
    _, template = SCAFFOLD.get(cwe, ("stdio", "import sys\n{FUNC}\nif __name__=='__main__': print('no template')"))
    call = build_call(func_name, params, cwe)
    return template.replace("{FUNC}", func_code).replace("{CALL}", call)


def process_entry(entry, cwe):
    """Process a raw entry into scaffolded vuln+patch code. Returns None if not viable."""
    vuln_raw = dedent_code(strip_self(entry["vulnerable"]))
    patch_raw = dedent_code(strip_self(entry["patched"]))

    name, params = get_func_info(vuln_raw)
    if not name:
        return None

    vuln_code = scaffold(vuln_raw, name, params, cwe)
    patch_code = scaffold(patch_raw, name, params, cwe)

    # Syntax check
    try:
        ast.parse(vuln_code)
        ast.parse(patch_code)
    except SyntaxError:
        return None

    # Runnability check: reject files with too many undefined names
    undef_count = count_undefined(vuln_code)
    if undef_count > 3:
        return None

    return name, params, vuln_code, patch_code, undef_count


def extract_sven():
    entries = defaultdict(list)
    for cwe, fname in SVEN_CWE_FILES.items():
        path = os.path.join(SVEN_TRAIN, fname)
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                if not line.strip():
                    continue
                e = json.loads(line)
                if not e.get("file_name", "").endswith(".py"):
                    continue
                if not e.get("func_src_before") or not e.get("func_src_after"):
                    continue
                if e["func_src_before"].count("\n") < 3:
                    continue
                entries[cwe].append({
                    "func_name": e.get("func_name", "unknown"),
                    "vulnerable": e["func_src_before"],
                    "patched": e["func_src_after"],
                    "commit": e.get("commit_link", ""),
                    "source": "sven",
                })
    return entries


def extract_pyvul():
    with open(PYVUL_CWE_MAP) as f:
        cwe_map = json.load(f)
    target_set = {c for c, _ in TARGET_CWES}
    entries = defaultdict(list)
    seen = set()
    with open(PYVUL_FUNC) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("programming_language") != "Python":
                continue
            commit = e.get("commit", "")
            cwe = cwe_map.get(commit, "Unknown")
            if cwe not in target_set:
                continue
            fn = e.get("function_name", "unknown")
            if not e.get("code_before") or not e.get("code_after"):
                continue
            if e["code_before"].count("\n") < 3:
                continue
            key = f"{commit}:{fn}"
            if key in seen:
                continue
            seen.add(key)
            entries[cwe].append({
                "func_name": fn,
                "vulnerable": e["code_before"],
                "patched": e["code_after"],
                "commit": commit,
                "source": "pyvul",
            })
    return entries


def build_dataset():
    vuln_dir = os.path.join(OUTPUT_BASE, "vulnerable")
    patch_dir = os.path.join(OUTPUT_BASE, "injectable")
    os.makedirs(vuln_dir, exist_ok=True)
    os.makedirs(patch_dir, exist_ok=True)

    print("Extracting SVEN entries...")
    sven = extract_sven()
    print("Extracting PyVul entries...")
    pyvul = extract_pyvul()

    manifest = []
    total = 0

    print(f"\n{'CWE':<10} {'Description':<40} {'SVEN':>5} {'PyVul':>5} {'Skip':>5} {'Used':>5}")
    print("-" * 75)

    for cwe, desc in TARGET_CWES:
        sven_pool = sven.get(cwe, [])
        pyvul_pool = pyvul.get(cwe, [])

        # Interleave for diversity
        all_candidates = []
        si, pi = 0, 0
        while si < len(sven_pool) or pi < len(pyvul_pool):
            if si < len(sven_pool):
                all_candidates.append(sven_pool[si])
                si += 1
            if pi < len(pyvul_pool):
                all_candidates.append(pyvul_pool[pi])
                pi += 1

        # Filter for runnability
        selected = []
        skipped = 0
        for entry in all_candidates:
            if len(selected) >= FILES_PER_CWE:
                break
            result = process_entry(entry, cwe)
            if result is None:
                skipped += 1
                continue
            name, params, vuln_code, patch_code, undef = result
            selected.append((entry, name, vuln_code, patch_code))

        sven_used = sum(1 for e, *_ in selected if e["source"] == "sven")
        pyvul_used = sum(1 for e, *_ in selected if e["source"] == "pyvul")

        for idx, (entry, name, vuln_code, patch_code) in enumerate(selected):
            fname = safe_filename(cwe, entry["source"], idx, name)
            with open(os.path.join(vuln_dir, fname), "w") as f:
                f.write(vuln_code)
            with open(os.path.join(patch_dir, fname), "w") as f:
                f.write(patch_code)
            manifest.append({
                "filename": fname, "cwe": cwe, "cwe_description": desc,
                "dataset": entry["source"], "func_name": name,
                "commit": entry.get("commit", ""),
            })

        written = len(selected)
        total += written
        tag = "✓" if written == FILES_PER_CWE else f"⚠ ({written})"
        print(f"{cwe:<10} {desc:<40} {sven_used:>5} {pyvul_used:>5} {skipped:>5} {written:>5} {tag}")

    with open(os.path.join(OUTPUT_BASE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nTotal: {total} file pairs written")
    if total < 100:
        print(f"WARNING: Only {total}/100 files passed runnability filter.")
        print("Some CWEs may not have enough self-contained functions in SVEN/PyVul.")
    return total


if __name__ == "__main__":
    build_dataset()
