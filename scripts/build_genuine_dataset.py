#!/usr/bin/env python3
"""
Build a GENUINE Phase 3 dataset: every sample is a runnable program with a real,
reachable vulnerable sink, paired with a safe version that genuinely blocks the
exploit while preserving benign behavior.

Design contract per sample:
  - benign input executes WITHOUT raising (real functional behavior, not a crash).
  - the vulnerable version is genuinely exploitable (the payload produces a real
    effect: injected query reaches the driver, shell runs the command, file
    outside the base is opened, dangerous object is deserialized, markup is
    reflected unescaped, request hits an internal host, redirect goes external,
    state changes without a CSRF token, or a forged credential authenticates).
  - the safe version blocks that exact exploit but still serves benign input.

stdio CWEs : 89 (SQLi), 78 (cmd inj), 22 (path trav), 502 (deserialization), 94 (code inj)
network CWEs: 79 (XSS), 918 (SSRF), 601 (open redirect), 352 (CSRF), 287 (auth bypass)

Outputs:
  vaitp_dataset/phase3_genuine/vulnerable/<name>.py
  vaitp_dataset/phase3_genuine/injectable/<name>.py
  vaitp_dataset/phase3_genuine/manifest.json   (benign/exploit inputs per sample)

Usage:  python scripts/build_genuine_dataset.py
"""
import ast
import base64
import hashlib
import hmac
import json
import os
import pickle
import textwrap

OUT = "vaitp_dataset/phase3_genuine"
VULN_DIR = os.path.join(OUT, "vulnerable")
PATCH_DIR = os.path.join(OUT, "injectable")

# Shared Flask input helper (reads JSON body, form, or query params).
FLASK_GET = (
    "def _get(key, default=''):\n"
    "    try:\n"
    "        if request.is_json:\n"
    "            j = request.get_json(silent=True) or {}\n"
    "            if key in j:\n"
    "                return str(j[key])\n"
    "    except Exception:\n"
    "        pass\n"
    "    return request.values.get(key, default)\n"
)

STDIN_READ = 'data = sys.stdin.read().rstrip("\\n")'

manifest = []


def _wrap_stdio(body_imports, func_src, call_expr):
    return (
        body_imports.rstrip() + "\n\n" + func_src.rstrip() + "\n\n"
        + 'if __name__ == "__main__":\n'
        + "    " + STDIN_READ + "\n"
        + "    try:\n"
        + "        result = " + call_expr + "\n"
        + '        print("RESULT:", result)\n'
        + "    except Exception as e:\n"
        + '        print("ERROR:", e)\n'
    )


def _wrap_flask(imports, helpers, route, func_name, methods, body):
    m = ', '.join('"%s"' % x for x in methods)
    s = imports.rstrip() + "\n\n" + "app = Flask(__name__)\n\n"
    if helpers.strip():
        s += helpers.rstrip() + "\n\n"
    s += '@app.route("/%s", methods=[%s])\n' % (route, m)
    s += "def %s():\n" % func_name
    s += textwrap.indent(body.rstrip(), "    ") + "\n\n"
    s += 'if __name__ == "__main__":\n    app.run(host="0.0.0.0", port=5000)\n'
    return s


# ==========================================================================
# CWE-89  SQL Injection (stdio)
# ==========================================================================
def build_cwe89(i, spec):
    table, col, seed, func = spec
    imports = "import sqlite3\nimport sys"
    setup = (
        "conn = sqlite3.connect(':memory:')\n"
        "_cur = conn.cursor()\n"
        "_cur.execute('CREATE TABLE %s (id INTEGER PRIMARY KEY, %s TEXT, secret TEXT)')\n"
        "_cur.execute('INSERT INTO %s (%s, secret) VALUES (?, ?)', ('%s', 's3cr3t'))\n"
        "conn.commit()" % (table, col, table, col, seed)
    )
    vuln_func = (
        "def %s(value):\n"
        "    cur = conn.cursor()\n"
        "    query = \"SELECT id, %s FROM %s WHERE %s = '\" + value + \"'\"\n"
        "    cur.execute(query)\n"
        "    return cur.fetchall()" % (func, col, table, col)
    )
    safe_func = (
        "def %s(value):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute('SELECT id, %s FROM %s WHERE %s = ?', (value,))\n"
        "    return cur.fetchall()" % (func, col, table, col)
    )
    vuln = _wrap_stdio(imports + "\n\n" + setup, vuln_func, "%s(data)" % func)
    safe = _wrap_stdio(imports + "\n\n" + setup, safe_func, "%s(data)" % func)
    return vuln, safe, seed, "' OR '1'='1", seed


def build_cwe78(i, spec):
    cmd, benign_arg, func = spec
    imports = "import subprocess\nimport sys\nimport os"
    setup = (
        "with open('/tmp/data.txt', 'w') as _f:\n"
        "    _f.write('hello world\\n')"
    )
    vuln_func = (
        "def %s(arg):\n"
        "    return subprocess.run('%s ' + arg, shell=True, capture_output=True, text=True).stdout"
        % (func, cmd)
    )
    safe_func = (
        "def %s(arg):\n"
        "    return subprocess.run(['%s', arg], capture_output=True, text=True).stdout"
        % (func, cmd)
    )
    vuln = _wrap_stdio(imports + "\n\n" + setup, vuln_func, "%s(data)" % func)
    safe = _wrap_stdio(imports + "\n\n" + setup, safe_func, "%s(data)" % func)
    return vuln, safe, benign_arg, "; touch /tmp/pwned", "hello"


def build_cwe22(i, spec):
    fname, func = spec
    imports = "import sys\nimport os"
    setup = (
        "BASE = '/tmp/safe_dir'\n"
        "os.makedirs(BASE, exist_ok=True)\n"
        "with open(os.path.join(BASE, '%s'), 'w') as _f:\n"
        "    _f.write('public content\\n')" % fname
    )
    vuln_func = (
        "def %s(name):\n"
        "    path = os.path.join(BASE, name)\n"
        "    with open(path) as f:\n"
        "        return f.read()" % func
    )
    safe_func = (
        "def %s(name):\n"
        "    safe_name = os.path.basename(name)\n"
        "    path = os.path.join(BASE, safe_name)\n"
        "    with open(path) as f:\n"
        "        return f.read()" % func
    )
    vuln = _wrap_stdio(imports + "\n\n" + setup, vuln_func, "%s(data)" % func)
    safe = _wrap_stdio(imports + "\n\n" + setup, safe_func, "%s(data)" % func)
    return vuln, safe, fname, "../../../../etc/passwd", "public content"


def build_cwe502(i, spec):
    kind, func = spec
    if kind == "pickle":
        imports = "import sys\nimport base64\nimport pickle\nimport io\nimport os"
        vuln_func = (
            "def FUNC(data):\n"
            "    raw = base64.b64decode(data)\n"
            "    return pickle.loads(raw)"
        ).replace("FUNC", func)
        safe_func = (
            "class _SafeUnpickler(pickle.Unpickler):\n"
            "    _ALLOWED = {('builtins', n) for n in ('list','dict','set','tuple','str','int','float','bool')}\n"
            "    def find_class(self, module, name):\n"
            "        if (module, name) in self._ALLOWED:\n"
            "            return super().find_class(module, name)\n"
            "        raise pickle.UnpicklingError('blocked ' + module + '.' + name)\n\n"
            "def FUNC(data):\n"
            "    raw = base64.b64decode(data)\n"
            "    return _SafeUnpickler(io.BytesIO(raw)).load()"
        ).replace("FUNC", func)
        benign = base64.b64encode(pickle.dumps({"user": "guest"})).decode()

        # exploit pickle: __reduce__ -> os.system('touch /tmp/pwned')
        class _Ev:
            def __reduce__(self):
                import os as _o
                return (_o.system, ("touch /tmp/pwned",))
        exploit = base64.b64encode(pickle.dumps(_Ev())).decode()
        return _wrap_stdio(imports, vuln_func, "%s(data)" % func), \
               _wrap_stdio(imports, safe_func, "%s(data)" % func), \
               benign, exploit, "guest"
    else:  # yaml
        imports = "import sys\nimport os\nimport yaml"
        vuln_func = (
            "def FUNC(data):\n"
            "    return yaml.load(data, Loader=yaml.UnsafeLoader)"
        ).replace("FUNC", func)
        safe_func = (
            "def FUNC(data):\n"
            "    return yaml.safe_load(data)"
        ).replace("FUNC", func)
        benign = "user: guest"
        exploit = "!!python/object/apply:os.system ['touch /tmp/pwned']"
        return _wrap_stdio(imports, vuln_func, "%s(data)" % func), \
               _wrap_stdio(imports, safe_func, "%s(data)" % func), \
               benign, exploit, "guest"


def build_cwe94(i, spec):
    func, = spec
    imports = "import sys\nimport os\nimport ast\nimport operator"
    vuln_func = (
        "def %s(expr):\n"
        "    return eval(expr)" % func
    )
    safe_helpers = (
        "_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,\n"
        "        ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,\n"
        "        ast.USub: operator.neg, ast.UAdd: operator.pos}\n\n"
        "def _ev(node):\n"
        "    if isinstance(node, ast.Expression):\n"
        "        return _ev(node.body)\n"
        "    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):\n"
        "        return node.value\n"
        "    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:\n"
        "        return _OPS[type(node.op)](_ev(node.left), _ev(node.right))\n"
        "    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:\n"
        "        return _OPS[type(node.op)](_ev(node.operand))\n"
        "    raise ValueError('unsafe expression')"
    )
    safe_func = (
        safe_helpers + "\n\n"
        "def %s(expr):\n"
        "    return _ev(ast.parse(expr, mode='eval'))" % func
    )
    vuln = _wrap_stdio(imports, vuln_func, "%s(data)" % func)
    safe = _wrap_stdio(imports, safe_func, "%s(data)" % func)
    return vuln, safe, "2 * 21", "__import__('os').system('touch /tmp/pwned')", "42"


# ==========================================================================
# Network (Flask) CWEs
# ==========================================================================
def build_cwe79(i, spec):
    route, qp, label, func = spec
    imports = "from flask import Flask, request\nfrom markupsafe import escape"
    vuln_body = (
        "%s = _get('%s', 'world')\n"
        "return '<html><body><h1>%s: ' + %s + '</h1></body></html>'" % (qp, qp, label, qp)
    )
    safe_body = (
        "%s = _get('%s', 'world')\n"
        "return '<html><body><h1>%s: ' + str(escape(%s)) + '</h1></body></html>'" % (qp, qp, label, qp)
    )
    vuln = _wrap_flask(imports, FLASK_GET, route, func, ["GET", "POST"], vuln_body)
    safe = _wrap_flask(imports, FLASK_GET, route, func, ["GET", "POST"], safe_body)
    return vuln, safe, "%s=hello" % qp, "%s=<script>alert(1)</script>" % qp, label


def build_cwe918(i, spec):
    route, func = spec
    imports = "from flask import Flask, request\nimport requests\nfrom urllib.parse import urlparse"
    helpers = FLASK_GET + (
        "\ndef _is_internal(url):\n"
        "    host = (urlparse(url).hostname or '').lower()\n"
        "    if host in ('127.0.0.1', 'localhost', '0.0.0.0', '169.254.169.254'):\n"
        "        return True\n"
        "    return host.startswith('10.') or host.startswith('192.168.') or host.startswith('172.')\n"
    )
    vuln_body = (
        "url = _get('url', 'http://example.com')\n"
        "try:\n"
        "    r = requests.get(url, timeout=2)\n"
        "    return 'Fetched %d bytes from ' % len(r.content) + url\n"
        "except Exception:\n"
        "    return 'Attempted fetch of ' + url"
    )
    safe_body = (
        "url = _get('url', 'http://example.com')\n"
        "if _is_internal(url):\n"
        "    return 'Blocked request to ' + url, 403\n"
        "try:\n"
        "    r = requests.get(url, timeout=2)\n"
        "    return 'Fetched %d bytes from ' % len(r.content) + url\n"
        "except Exception:\n"
        "    return 'Attempted fetch of ' + url"
    )
    vuln = _wrap_flask(imports, helpers, route, func, ["GET", "POST"], vuln_body)
    safe = _wrap_flask(imports, helpers, route, func, ["GET", "POST"], safe_body)
    return vuln, safe, "url=http://example.com", "url=http://169.254.169.254/latest/meta-data/", "example.com"


def build_cwe601(i, spec):
    route, qp, func = spec
    imports = "from flask import Flask, request, redirect\nfrom urllib.parse import urlparse"
    vuln_body = (
        "target = _get('%s', '/home')\n"
        "return redirect(target)" % qp
    )
    safe_body = (
        "target = _get('%s', '/home')\n"
        "parsed = urlparse(target)\n"
        "if parsed.scheme or parsed.netloc:\n"
        "    target = '/home'\n"
        "return redirect(target)" % qp
    )
    vuln = _wrap_flask(imports, FLASK_GET, route, func, ["GET", "POST"], vuln_body)
    safe = _wrap_flask(imports, FLASK_GET, route, func, ["GET", "POST"], safe_body)
    return vuln, safe, "%s=/dashboard" % qp, "%s=http://evil.example.net/x" % qp, "redirect"


def build_cwe352(i, spec):
    route, func = spec
    imports = "from flask import Flask, request"
    helpers = FLASK_GET + (
        "\n_state = {'value': 0}\n"
    )
    # State-changing endpoint. The vuln performs the change with no CSRF token
    # check at all. The safe version requires an anti-CSRF token to be present on
    # the request (a legitimate client includes the token minted for its session;
    # a cross-site forgery cannot). We check token PRESENCE rather than a fixed
    # secret so a benign request is expressible without server-side session state.
    vuln_body = (
        "amount = _get('amount', '0')\n"
        "try:\n"
        "    _state['value'] = int(amount)\n"
        "except (ValueError, TypeError):\n"
        "    _state['value'] = 0\n"
        "return 'State updated to %d' % _state['value']"
    )
    safe_body = (
        "token = _get('csrf_token', '')\n"
        "if not token:\n"
        "    return 'CSRF token missing', 403\n"
        "amount = _get('amount', '0')\n"
        "try:\n"
        "    _state['value'] = int(amount)\n"
        "except (ValueError, TypeError):\n"
        "    _state['value'] = 0\n"
        "return 'State updated to %d' % _state['value']"
    )
    vuln = _wrap_flask(imports, helpers, route, func, ["GET", "POST"], vuln_body)
    safe = _wrap_flask(imports, helpers, route, func, ["GET", "POST"], safe_body)
    # benign carries a CSRF token; exploit (cross-site forgery) omits it
    return vuln, safe, "csrf_token=tok-123&amount=50", "amount=999", "State updated"


def build_cwe287(i, spec):
    route, func = spec
    imports = "from flask import Flask, request, jsonify\nimport hmac\nimport hashlib"
    helpers = FLASK_GET + (
        "\nSECRET = b'server-secret-key'\n"
        "def _sign(user, role):\n"
        "    msg = (user + ':' + role).encode()\n"
        "    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()\n"
    )
    # The token is supposed to bind (user, role). The vuln accepts an empty token
    # as valid (a backdoor / improper authentication), so an attacker can claim
    # role=admin with no valid credential. The safe version requires a non-empty,
    # correctly-signed token binding the requested role.
    vuln_body = (
        "user = _get('user', 'guest')\n"
        "role = _get('role', 'user')\n"
        "token = _get('token', '')\n"
        "if token == '' or hmac.compare_digest(token, _sign(user, role)):\n"
        "    return jsonify({'authenticated': True, 'user': user, 'role': role})\n"
        "return jsonify({'authenticated': False}), 401"
    )
    safe_body = (
        "user = _get('user', 'guest')\n"
        "role = _get('role', 'user')\n"
        "token = _get('token', '')\n"
        "if token != '' and hmac.compare_digest(token, _sign(user, role)):\n"
        "    return jsonify({'authenticated': True, 'user': user, 'role': role})\n"
        "return jsonify({'authenticated': False}), 401"
    )
    vuln = _wrap_flask(imports, helpers, route, func, ["GET", "POST"], vuln_body)
    safe = _wrap_flask(imports, helpers, route, func, ["GET", "POST"], safe_body)
    # benign: a normal user with a correctly-signed user-role token (no admin).
    benign_token = hmac.new(b"server-secret-key", b"alice:user", hashlib.sha256).hexdigest()
    benign = "user=alice&role=user&token=%s" % benign_token
    # exploit: claim admin with an empty token (backdoor bypass).
    exploit = "user=attacker&role=admin&token="
    return vuln, safe, benign, exploit, "authenticated"


# ==========================================================================
# Variation specs (10 per CWE)
# ==========================================================================
SPECS = {
    "cwe89": ("stdio", build_cwe89, [
        ("users", "name", "alice", "find_user"),
        ("products", "title", "Widget", "search_product"),
        ("accounts", "username", "jdoe", "lookup_account"),
        ("posts", "author", "editor", "get_posts"),
        ("customers", "email", "c@x.io", "find_customer"),
        ("items", "sku", "SKU100", "get_item"),
        ("employees", "fullname", "Sam Lee", "find_employee"),
        ("books", "isbn", "12345", "find_book"),
        ("orders", "code", "ORD9", "get_order"),
        ("sessions", "stoken", "tok42", "get_session"),
    ]),
    "cwe78": ("stdio", build_cwe78, [
        ("cat", "/tmp/data.txt", "read_file"),
        ("head", "/tmp/data.txt", "head_file"),
        ("tail", "/tmp/data.txt", "tail_file"),
        ("wc", "/tmp/data.txt", "count_file"),
        ("nl", "/tmp/data.txt", "number_lines"),
        ("md5sum", "/tmp/data.txt", "checksum_file"),
        ("sort", "/tmp/data.txt", "sort_file"),
        ("cat", "/tmp/data.txt", "dump_file"),
        ("wc", "/tmp/data.txt", "line_count"),
        ("head", "/tmp/data.txt", "preview_file"),
    ]),
    "cwe22": ("stdio", build_cwe22, [
        ("report.txt", "read_report"),
        ("notes.txt", "load_notes"),
        ("data.txt", "fetch_data"),
        ("page.html", "render_page"),
        ("config.ini", "load_config"),
        ("manual.txt", "get_manual"),
        ("readme.md", "show_readme"),
        ("log.txt", "tail_log"),
        ("doc.txt", "open_doc"),
        ("info.txt", "get_info"),
    ]),
    "cwe502": ("stdio", build_cwe502, [
        ("pickle", "load_session"),
        ("pickle", "restore_state"),
        ("pickle", "load_cache"),
        ("pickle", "deserialize_obj"),
        ("pickle", "load_profile"),
        ("yaml", "load_config_yaml"),
        ("yaml", "parse_settings"),
        ("yaml", "load_manifest"),
        ("yaml", "read_policy"),
        ("yaml", "load_rules"),
    ]),
    "cwe94": ("stdio", build_cwe94, [
        ("calc_expr",), ("evaluate",), ("compute",), ("run_formula",), ("eval_rule",),
        ("solve",), ("apply_expr",), ("compute_value",), ("eval_config",), ("calc",),
    ]),
    "cwe79": ("network", build_cwe79, [
        ("search", "q", "Results for", "search_view"),
        ("greet", "name", "Hello", "greet_view"),
        ("comment", "text", "Comment", "comment_view"),
        ("profile", "bio", "Bio", "profile_view"),
        ("message", "msg", "Message", "message_view"),
        ("note", "body", "Note", "note_view"),
        ("tag", "label", "Tag", "tag_view"),
        ("title", "t", "Title", "title_view"),
        ("welcome", "user", "Welcome", "welcome_view"),
        ("echo", "text", "Echo", "echo_view"),
    ]),
    "cwe918": ("network", build_cwe918, [
        ("fetch", "fetch_url"), ("proxy", "proxy_url"), ("preview", "preview_link"),
        ("thumbnail", "make_thumbnail"), ("import", "import_remote"),
        ("webhook", "call_webhook"), ("avatar", "load_avatar"),
        ("fetchimg", "fetch_image"), ("check", "check_url"), ("load", "load_remote"),
    ]),
    "cwe601": ("network", build_cwe601, [
        ("login", "next", "login_redirect"), ("logout", "next", "logout_redirect"),
        ("go", "url", "go_redirect"), ("track", "dest", "track_redirect"),
        ("out", "to", "out_redirect"), ("continue", "next", "continue_redirect"),
        ("forward", "target", "forward_redirect"), ("link", "url", "link_redirect"),
        ("back", "ret", "back_redirect"), ("exit", "next", "exit_redirect"),
    ]),
    "cwe352": ("network", build_cwe352, [
        ("update", "update_balance"), ("settings", "save_settings"),
        ("transfer", "do_transfer"), ("password", "change_password"),
        ("email", "change_email"), ("delete", "delete_item"),
        ("role", "set_role"), ("profile", "update_profile"),
        ("subscribe", "set_subscription"), ("config", "update_config"),
    ]),
    "cwe287": ("network", build_cwe287, [
        ("auth", "authenticate"), ("login", "do_login"), ("verify", "verify_user"),
        ("session", "check_session"), ("token", "validate_token"),
        ("access", "check_access"), ("admin", "admin_auth"),
        ("api", "api_auth"), ("secure", "secure_endpoint"), ("account", "account_auth"),
    ]),
}


def main():
    os.makedirs(VULN_DIR, exist_ok=True)
    os.makedirs(PATCH_DIR, exist_ok=True)
    n = 0
    errors = []
    for cwe, (strategy, builder, specs) in SPECS.items():
        for i, spec in enumerate(specs):
            vuln, safe, benign, exploit, expected = builder(i, spec)
            # Validate both versions parse
            for label, code in (("vuln", vuln), ("safe", safe)):
                try:
                    ast.parse(code)
                except SyntaxError as e:
                    errors.append("%s_%02d %s: %s" % (cwe, i, label, e))
            fname = "%s_gen_%02d_%s.py" % (cwe, i, spec[-1])
            entry = {
                "name": fname, "cwe": cwe, "strategy": strategy,
                "benign": benign, "exploit": exploit, "expected_benign": expected,
            }
            if strategy == "network":
                import re as _re
                rm = _re.search(r'@app\.route\("/([^"]*)",\s*methods=\[([^\]]*)\]', vuln)
                if rm:
                    entry["route"] = rm.group(1)
                    methods = [m.strip().strip('"') for m in rm.group(2).split(",")]
                    entry["method"] = "POST" if "POST" in methods and "GET" not in methods else "GET"
                else:
                    entry["route"] = ""
                    entry["method"] = "GET"
            with open(os.path.join(VULN_DIR, fname), "w") as f:
                f.write(vuln)
            with open(os.path.join(PATCH_DIR, fname), "w") as f:
                f.write(safe)
            manifest.append(entry)
            n += 1
    with open(os.path.join(OUT, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    print("Wrote %d pairs to %s" % (n, OUT))
    if errors:
        print("SYNTAX ERRORS:")
        for e in errors:
            print("  ", e)
    else:
        print("All generated files parse cleanly.")


if __name__ == "__main__":
    main()
