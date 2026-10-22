"""
Side-Effect Injector for Phase 3 Verification (effect-based).

Instruments Python code so that a side-effect marker file (e.g. /tmp/pwned) is
created ONLY when the *exploitation effect* actually occurs — not merely when a
malicious-looking input arrives or a sink is reached.

This distinction is critical for the Double-Check Methodology. The same detector
is applied to BOTH the vulnerable and the patched code (symmetric instrumentation);
a genuine exploit therefore fires the detector on the vulnerable version and stays
silent on the patched version, turning Condition 4 ("the safe code blocks the
exploit") into a true differential test.

Design principle: every detector keys on a *condition that constitutes
exploitation*, evaluated on what the program actually does, e.g.:
  - SQLi      : injection metacharacters appear IN THE QUERY STRING passed to the
                DB driver (a parameterized query keeps user input out of the query
                string, so the detector stays silent).
  - Path trav.: the path the program actually open()s escapes the intended base
                directory or reaches a sensitive location (a fix that confines the
                path keeps it inside the base).
  - Deserial. : the bytes actually handed to pickle.loads / yaml.load contain
                dangerous opcodes/tags under an unsafe loader.
  - SSRF      : an outbound request is actually made to an internal/metadata host.
  - XSS       : the attacker's markup is reflected UNESCAPED in the response body.
  - Open redir: a 3xx Location header points to an attacker-controlled external host.
  - Auth byp. : the response grants authorization for a forged/invalid credential.
  - CSRF      : a state-changing request lacking a valid token is accepted.

Detectors that only observed the *input* (injection characters in the request,
markers in stdin) have been removed: they fired identically on vulnerable and
patched code and therefore measured sink-reachability, not exploitation.
"""
import re
import logging
import textwrap
from typing import Optional

logger = logging.getLogger(__name__)

_SF = "__SUCCESS_FILE__"   # sentinel replaced with the success_file path
_APP = "__APP_VAR__"        # sentinel replaced with the Flask app variable name


def inject_side_effect(source_code: str, success_file: str,
                       strategy: str = "network", category: Optional[str] = None) -> str:
    """
    Instrument Python source to create `success_file` when the exploitation
    effect occurs.

    Args:
        source_code: Original Python source.
        success_file: Marker file path created on exploitation (e.g. /tmp/pwned).
        strategy: "network" (Flask/web) or "stdio" (stdin-based CLI).
        category: Vulnerability category (from classify_vuln_from_code). When
                  provided, only the relevant response-effect detector is wired
                  for network apps. Library-level effect detectors are always
                  installed (they only fire on the actual dangerous operation).

    Returns:
        Instrumented source code.
    """
    if success_file in source_code:
        logger.debug(f"Code already contains '{success_file}', skipping injection")
        return source_code

    source_code = _ensure_import_os(source_code)
    category = (category or "").lower()

    if strategy == "network":
        return _inject_network(source_code, success_file, category)
    return _inject_stdio(source_code, success_file, category)


def _ensure_import_os(code: str) -> str:
    """Add 'import os' if not present (needed by the detectors)."""
    if re.search(r'^\s*import\s+os\b', code, re.MULTILINE):
        return code
    if re.search(r'^\s*from\s+os\s+import', code, re.MULTILINE):
        return code
    lines = code.split('\n')
    last_import_idx = -1
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith('import ') or s.startswith('from '):
            last_import_idx = i
    if last_import_idx >= 0:
        lines.insert(last_import_idx + 1, 'import os')
    else:
        lines.insert(0, 'import os')
    return '\n'.join(lines)


# ==========================================================================
# Shared library-level effect detectors (effect-based, category-independent).
# Each only fires on the ACTUAL dangerous operation, so a patch that avoids the
# operation (parameterized query, safe loader, confined path, blocked host)
# leaves the detector silent.
# ==========================================================================
_MONKEYPATCHES = r'''
# --- VAITP effect-based instrumentation (auto-injected) ---
import os as _vaitp_os

def _vaitp_fire():
    """Create the marker file. Idempotent."""
    try:
        _vaitp_os.system('touch __SUCCESS_FILE__')
    except Exception:
        pass

# SQL injection: fire only when injection metacharacters appear IN THE QUERY
# STRING handed to the driver. Parameterized queries keep user input in the
# parameter tuple (args), so the query string itself stays clean -> silent.
def _vaitp_sql_is_injected(sql, args):
    if args:                      # parameterized call -> not an injected query
        return False
    if not isinstance(sql, (str, bytes)):
        return False
    q = sql if isinstance(sql, str) else sql.decode('utf-8', 'ignore')
    markers = ["' OR ", "' or ", "' AND ", "' and ", "UNION SELECT", "union select",
               "OR '1'='1", "or '1'='1", "1'='1", "OR 1=1", "or 1=1", "'='",
               "'--", "' --", ";--", "ATTACH DATABASE", "attach database",
               "; DROP", "; drop", "'; ", "UNION ALL", "union all"]
    return any(m in q for m in markers)

try:
    import sqlite3 as _vaitp_sqlite3
    _vaitp_orig_connect = _vaitp_sqlite3.connect
    # sqlite3.Cursor/Connection are immutable C types (cannot monkey-patch their
    # methods). Subclasses CAN override, so we inject our subclasses via the
    # connection/cursor `factory` argument. This is a real Connection, so normal
    # DB behaviour (commit, context manager, row_factory) is preserved.
    class _VaitpCursor(_vaitp_sqlite3.Cursor):
        def execute(self, sql, *a, **k):
            if _vaitp_sql_is_injected(sql, a or k):
                _vaitp_fire()
            return super().execute(sql, *a, **k)
        def executescript(self, sql):
            q = sql if isinstance(sql, str) else str(sql)
            if 'ATTACH DATABASE' in q or 'attach database' in q:
                _vaitp_fire()
            return super().executescript(sql)
    class _VaitpConnection(_vaitp_sqlite3.Connection):
        def cursor(self, *a, **k):
            k.setdefault('factory', _VaitpCursor)
            return super().cursor(*a, **k)
        def execute(self, sql, *a, **k):
            if _vaitp_sql_is_injected(sql, a or k):
                _vaitp_fire()
            return super().execute(sql, *a, **k)
        def executescript(self, sql):
            q = sql if isinstance(sql, str) else str(sql)
            if 'ATTACH DATABASE' in q or 'attach database' in q:
                _vaitp_fire()
            return super().executescript(sql)
    def _vaitp_connect(*a, **k):
        k.setdefault('factory', _VaitpConnection)
        return _vaitp_orig_connect(*a, **k)
    _vaitp_sqlite3.connect = _vaitp_connect
except Exception:
    pass

try:
    import MySQLdb.cursors as _vaitp_mysqlc
    _vaitp_orig_mysql_exec = _vaitp_mysqlc.BaseCursor.execute
    def _vaitp_mysql_exec(self, query, args=None):
        if _vaitp_sql_is_injected(query, args):
            _vaitp_fire()
        return _vaitp_orig_mysql_exec(self, query, args)
    _vaitp_mysqlc.BaseCursor.execute = _vaitp_mysql_exec
except Exception:
    pass

try:
    import pymysql.cursors as _vaitp_pymysqlc
    _vaitp_orig_pymysql_exec = _vaitp_pymysqlc.Cursor.execute
    def _vaitp_pymysql_exec(self, query, args=None):
        if _vaitp_sql_is_injected(query, args):
            _vaitp_fire()
        return _vaitp_orig_pymysql_exec(self, query, args)
    _vaitp_pymysqlc.Cursor.execute = _vaitp_pymysql_exec
except Exception:
    pass

# Insecure deserialization (pickle): fire only when the bytes actually handed to
# pickle.loads carry dangerous opcodes (an RCE gadget), not benign dicts/lists.
try:
    import pickle as _vaitp_pickle
    _vaitp_orig_ploads = _vaitp_pickle.loads
    def _vaitp_ploads(data, *a, **k):
        raw = data if isinstance(data, bytes) else (
            data.encode('latin-1', 'ignore') if isinstance(data, str) else b'')
        if any(d in raw for d in (b'posix', b'nt', b'subprocess', b'system',
                                   b'popen', b'commands', b'__reduce__', b'builtins\neval')):
            _vaitp_fire()
        return _vaitp_orig_ploads(data, *a, **k)
    _vaitp_pickle.loads = _vaitp_ploads
except Exception:
    pass

# Insecure deserialization (YAML): fire only under an unsafe loader AND with
# dangerous tags actually present. SafeLoader/BaseLoader patches stay silent.
try:
    import yaml as _vaitp_yaml
    def _vaitp_yaml_danger(data):
        raw = str(data) if data is not None else ''
        return any(t in raw for t in ('!!python/', '__import__', 'os.system',
                                      'subprocess', 'apply:', '!!python/object'))
    _vaitp_orig_yload = _vaitp_yaml.load
    def _vaitp_yload(data, *a, **k):
        loader = k.get('Loader') or (a[0] if a else None)
        is_safe = loader is not None and ('Safe' in str(loader) or 'Base' in str(loader))
        if not is_safe and _vaitp_yaml_danger(data):
            _vaitp_fire()
        return _vaitp_orig_yload(data, *a, **k)
    _vaitp_yaml.load = _vaitp_yload
    if hasattr(_vaitp_yaml, 'unsafe_load'):
        _vaitp_orig_uyload = _vaitp_yaml.unsafe_load
        def _vaitp_uyload(data, *a, **k):
            if _vaitp_yaml_danger(data):
                _vaitp_fire()
            return _vaitp_orig_uyload(data, *a, **k)
        _vaitp_yaml.unsafe_load = _vaitp_uyload
except Exception:
    pass

# Code injection (eval): fire only when the REAL builtins.eval is invoked on a
# dangerous expression. A fix using ast.literal_eval never calls builtins.eval.
try:
    import builtins as _vaitp_builtins
    _vaitp_orig_eval = _vaitp_builtins.eval
    def _vaitp_eval(*a, **k):
        if a:
            s = a[0] if isinstance(a[0], str) else str(a[0])
            if any(d in s for d in ('__import__', 'os.system', 'os.popen',
                                    'subprocess', 'open(', 'commands', 'eval(', 'exec(')):
                _vaitp_fire()
        return _vaitp_orig_eval(*a, **k)
    _vaitp_builtins.eval = _vaitp_eval
except Exception:
    pass

# SSRF: fire only when an outbound request is actually made to an internal or
# cloud-metadata host. A fix that blocks/validates the host never makes the call.
def _vaitp_is_internal(url):
    u = str(url).lower()
    return any(h in u for h in ('127.0.0.1', 'localhost', '0.0.0.0', '169.254.',
                                '://10.', '://172.16.', '://172.17.', '://192.168.',
                                '[::1]', 'metadata.google', '169.254.169.254'))
try:
    import requests as _vaitp_requests
    _vaitp_orig_rget = _vaitp_requests.get
    _vaitp_orig_rpost = _vaitp_requests.post
    def _vaitp_rget(url, *a, **k):
        if _vaitp_is_internal(url):
            _vaitp_fire()
        return _vaitp_orig_rget(url, *a, **k)
    def _vaitp_rpost(url, *a, **k):
        if _vaitp_is_internal(url):
            _vaitp_fire()
        return _vaitp_orig_rpost(url, *a, **k)
    _vaitp_requests.get = _vaitp_rget
    _vaitp_requests.post = _vaitp_rpost
except Exception:
    pass
try:
    import urllib.request as _vaitp_ureq
    _vaitp_orig_uopen = _vaitp_ureq.urlopen
    def _vaitp_uopen(url, *a, **k):
        if _vaitp_is_internal(url):
            _vaitp_fire()
        return _vaitp_orig_uopen(url, *a, **k)
    _vaitp_ureq.urlopen = _vaitp_uopen
except Exception:
    pass

# JWT: fire only on an actual insecure verification (alg "none" or signature
# verification disabled). A fix that pins a strong algorithm stays silent.
try:
    import jwt as _vaitp_jwt
    _vaitp_orig_jwtdec = _vaitp_jwt.decode
    def _vaitp_jwtdec(token, *a, **k):
        algs = k.get('algorithms', []) or []
        opts = k.get('options', {}) or {}
        alg_l = [str(x).lower() for x in algs]
        if 'none' in alg_l or opts.get('verify_signature') is False:
            _vaitp_fire()
        return _vaitp_orig_jwtdec(token, *a, **k)
    _vaitp_jwt.decode = _vaitp_jwtdec
except Exception:
    pass

# Path traversal: fire only when the program actually open()s a path that escapes
# the intended base directory or reaches a sensitive location. A fix that strips
# "../" / confines the path keeps the opened path inside the base -> silent.
# This inspects the post-sanitization path the code really opens (effect), not
# the raw request input.
try:
    import builtins as _vaitp_b2
    _vaitp_orig_open = _vaitp_b2.open
    _vaitp_bases = [_vaitp_os.path.abspath(b) for b in
                    ('/app', '/tmp/safe_dir', _vaitp_os.getcwd())]
    _vaitp_sensitive = ('/etc/', '/root/', '/proc/', '/sys/', '/var/lib')
    def _vaitp_open(file, *a, **k):
        try:
            p = str(file)
            ap = _vaitp_os.path.abspath(_vaitp_os.path.normpath(p))
            inside = any(ap == b or ap.startswith(b + _vaitp_os.sep)
                         for b in _vaitp_bases)
            if not inside and (('..' in p) or any(s in ap for s in _vaitp_sensitive)):
                _vaitp_fire()
        except Exception:
            pass
        return _vaitp_orig_open(file, *a, **k)
    _vaitp_b2.open = _vaitp_open
except Exception:
    pass
# --- end VAITP library detectors ---
'''


def _monkeypatch_block(success_file: str) -> str:
    return _MONKEYPATCHES.replace(_SF, success_file)


# ==========================================================================
# Network (Flask) response-effect detectors.
# ==========================================================================
def _find_flask_app_var(code: str) -> Optional[str]:
    m = re.search(r'^(\w+)\s*=\s*Flask\s*\(', code, re.MULTILINE)
    return m.group(1) if m else None


# Categories that warrant each response-effect detector. Library-level effects
# (SQLi, SSRF, deserialization, etc.) are handled by the monkey-patches above
# and need no response hook.
_XSS_CATS = {"xss", "ssti", "mako", "generic", "flask_network", "unknown", ""}
_REDIR_CATS = {"open_redirect", "generic", "flask_network", "unknown", ""}
_AUTH_CATS = {"auth", "improper_auth", "jwt", "nosql", "generic", "flask_network", "unknown", ""}
# CSRF detection ("a state-changing POST without a valid token is accepted") is
# deliberately gated to the csrf category ONLY. It must NOT be enabled for
# generic/flask_network apps: non-CSRF endpoints (XSS, redirect, SSRF) also accept
# POST without a token and return 2xx, which would false-fire on their safe
# versions and break the patch-blocks check. The orchestrator assigns the precise
# category for known-CWE dataset files, so csrf apps are detected exactly.
_CSRF_CATS = {"csrf"}


def _build_flask_hook(app_var: str, success_file: str, category: str) -> str:
    enable_xss = category in _XSS_CATS
    enable_redir = category in _REDIR_CATS
    enable_auth = category in _AUTH_CATS
    enable_csrf = category in _CSRF_CATS

    hook = r'''
# --- VAITP response-effect detector (auto-injected) ---
import re as _vaitp_re
import urllib.parse as _vaitp_up
from flask import request as _vaitp_req, g as _vaitp_g

_VAITP_XSS = __ENABLE_XSS__
_VAITP_REDIR = __ENABLE_REDIR__
_VAITP_AUTH = __ENABLE_AUTH__
_VAITP_CSRF = __ENABLE_CSRF__

@__APP_VAR__.before_request
def _vaitp_stash():
    try:
        raw = _vaitp_req.query_string.decode('utf-8', 'ignore')
        raw += " " + (_vaitp_req.get_data(as_text=True) or "")
        decoded = _vaitp_up.unquote(raw)
        _vaitp_g._vaitp_in = decoded
        # Format-agnostic CSRF-token presence: look for a csrf/token field in the
        # full request (query + body), so JSON, form, and query delivery all work.
        low = decoded.lower()
        _vaitp_g._vaitp_has_token = ('csrf' in low) or ('token' in low)
        _vaitp_g._vaitp_method = _vaitp_req.method
    except Exception:
        _vaitp_g._vaitp_in = ""
        _vaitp_g._vaitp_has_token = False
        _vaitp_g._vaitp_method = "GET"

def _vaitp_xss_tokens(raw):
    # Extract HTML/JS-significant tokens that, if reflected verbatim, prove the
    # markup was NOT escaped by the application.
    toks = []
    for m in _vaitp_re.findall(r'<\s*/?\s*(?:script|img|svg|iframe|body|a|div)[^>]*>?', raw, _vaitp_re.I):
        if len(m) >= 4:
            toks.append(m)
    for m in _vaitp_re.findall(r'(?:onerror|onload|onclick)\s*=', raw, _vaitp_re.I):
        toks.append(m)
    if 'javascript:' in raw.lower():
        toks.append('javascript:')
    return toks

@__APP_VAR__.after_request
def _vaitp_effect(response):
    try:
        raw = getattr(_vaitp_g, '_vaitp_in', '') or ''
        status = response.status_code
        body = ''
        try:
            body = response.get_data(as_text=True) or ''
        except Exception:
            body = ''

        # XSS effect: an HTML/JS token from the input is reflected UNESCAPED in
        # the response body. A fix that escapes output turns '<' into '&lt;', so
        # the verbatim token is absent -> silent.
        if _VAITP_XSS and raw:
            for tok in _vaitp_xss_tokens(raw):
                if tok and tok in body:
                    _vaitp_fire()
                    break

        # Open-redirect effect: a 3xx response whose Location points to an
        # attacker-controlled EXTERNAL host that appeared in the input. A fix
        # that forces relative/same-origin redirects emits a relative Location.
        # Compare the real hostname a browser would visit, not the raw netloc:
        # in http://attacker.com@127.0.0.1/ the part before '@' is only userinfo,
        # so the browser stays on 127.0.0.1 and nothing was redirected off-site.
        if _VAITP_REDIR and 300 <= status < 400:
            loc = (response.headers.get('Location', '') or '').strip()
            low = loc.lower()
            is_absolute_external = low.startswith('http://') or low.startswith('https://') or low.startswith('//')
            if is_absolute_external:
                try:
                    host = (_vaitp_up.urlparse(loc).hostname or '').lower().rstrip('.')
                except Exception:
                    host = ''
                try:
                    own = (_vaitp_up.urlparse('//' + _vaitp_req.host).hostname or '').lower()
                except Exception:
                    own = ''
                is_local = (host in ('localhost', '0.0.0.0', '::1', own)
                            or host.startswith('127.') or host.endswith('.localhost'))
                if host and not is_local and host in raw.lower():
                    _vaitp_fire()

        # Auth-bypass effect: the response grants a PRIVILEGED role (admin) that a
        # benign user would not receive. During the exploit check the input is a
        # forged/invalid credential, so an admin-level response means the bypass
        # worked. A benign valid login returns a normal role (user) -> silent.
        # A correct fix rejects the forged credential -> 401 / no admin -> silent.
        if _VAITP_AUTH:
            compact = body.lower().replace(" ", "")
            privileged = any(s in compact for s in (
                '"role":"admin"', '"role":"administrator"', '"role":"root"',
                '"is_admin":true', '"admin":true', '"isadmin":true',
                '"privilege":"admin"', '"access":"admin"',
            ))
            if privileged:
                _vaitp_fire()

        # CSRF effect: a state-changing request lacking a CSRF token is accepted
        # (2xx, no error). A fix (CSRF protection) rejects it with 4xx -> silent.
        if _VAITP_CSRF:
            method = getattr(_vaitp_g, '_vaitp_method', 'GET')
            has_token = getattr(_vaitp_g, '_vaitp_has_token', False)
            if method in ('POST', 'PUT', 'DELETE', 'PATCH') and not has_token and 200 <= status < 300:
                _vaitp_fire()
    except Exception:
        pass
    return response
# --- end VAITP response-effect detector ---
'''
    hook = (hook.replace("__APP_VAR__", app_var)
                .replace("__ENABLE_XSS__", str(enable_xss))
                .replace("__ENABLE_REDIR__", str(enable_redir))
                .replace("__ENABLE_AUTH__", str(enable_auth))
                .replace("__ENABLE_CSRF__", str(enable_csrf)))
    return hook


def _inject_network(code: str, success_file: str, category: str) -> str:
    """Insert shared library detectors + a category-aware response-effect hook."""
    code = _insert_after_imports(code, _monkeypatch_block(success_file))

    app_var = _find_flask_app_var(code)
    if not app_var:
        logger.warning("No Flask app var found; relying on library detectors only")
        return code

    hook = _build_flask_hook(app_var, success_file, category)

    lines = code.split('\n')
    insert_idx = None
    for i, line in enumerate(lines):
        if re.match(rf'^\s*{re.escape(app_var)}\s*=\s*Flask\s*\(', line):
            insert_idx = i + 1
            break
    if insert_idx is None:
        for i, line in enumerate(lines):
            if f'@{app_var}.route' in line:
                insert_idx = i
                break
    if insert_idx is None:
        logger.warning("No insertion point for Flask hook; library detectors only")
        return code
    lines.insert(insert_idx, hook)
    return '\n'.join(lines)


def _inject_stdio(code: str, success_file: str, category: str) -> str:
    """Insert shared library detectors only.

    Natural exploits (command injection via the shell, eval-based code injection)
    create the marker file directly through the payload, so no input-based
    detector is needed. The library detectors above cover SQLi, deserialization,
    YAML, eval, and path traversal at the effect level.
    """
    return _insert_after_imports(code, _monkeypatch_block(success_file))


def _insert_after_imports(code: str, block: str) -> str:
    lines = code.split('\n')
    last_import_idx = -1
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith('import ') or s.startswith('from '):
            last_import_idx = i
    if last_import_idx >= 0:
        lines.insert(last_import_idx + 1, block)
    else:
        lines.insert(0, block)
    return '\n'.join(lines)
