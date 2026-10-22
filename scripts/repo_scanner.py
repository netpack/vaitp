"""
Repository Scanner for VAITP Framework.

Selects, downloads, and queues Python repositories for vulnerability review
using the VAITP framework. Targets small but widely-used Python packages
where finding zero-day vulnerabilities has high impact.

Usage:
    python scripts/repo_scanner.py --list          # Show top 100 target repos
    python scripts/repo_scanner.py --download N    # Download top N repos
    python scripts/repo_scanner.py --scan REPO     # Run VAITP scan on a repo
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Base directory for cloned repos
REPOS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "target_repos")

# Top 100 small, widely-used Python packages (sorted by downloads/impact, filtered for small codebase)
# Criteria: <10k LOC in core, >1M monthly downloads, pure Python or mostly Python
# These are ideal targets: small enough to review thoroughly, used enough that vulns matter.
TARGET_REPOSITORIES: List[Dict] = [
    # --- Web/HTTP utilities ---
    {"name": "urllib3", "repo": "urllib3/urllib3", "category": "http", "monthly_downloads": "200M+", "reason": "HTTP client used by requests"},
    {"name": "certifi", "repo": "certifi/python-certifi", "category": "crypto", "monthly_downloads": "200M+", "reason": "CA certificate bundle"},
    {"name": "idna", "repo": "kjd/idna", "category": "network", "monthly_downloads": "200M+", "reason": "Internationalized domain names"},
    {"name": "charset-normalizer", "repo": "Ousret/charset_normalizer", "category": "encoding", "monthly_downloads": "180M+", "reason": "Character encoding detection"},
    {"name": "requests", "repo": "psf/requests", "category": "http", "monthly_downloads": "150M+", "reason": "HTTP library"},
    {"name": "httpx", "repo": "encode/httpx", "category": "http", "monthly_downloads": "30M+", "reason": "Async HTTP client"},
    {"name": "aiohttp", "repo": "aio-libs/aiohttp", "category": "http", "monthly_downloads": "40M+", "reason": "Async HTTP framework"},

    # --- Serialization/Parsing ---
    {"name": "pyyaml", "repo": "yaml/pyyaml", "category": "serialization", "monthly_downloads": "100M+", "reason": "YAML parser (history of RCE)"},
    {"name": "tomli", "repo": "hukkin/tomli", "category": "serialization", "monthly_downloads": "100M+", "reason": "TOML parser"},
    {"name": "ujson", "repo": "ultrajson/ultrajson", "category": "serialization", "monthly_downloads": "20M+", "reason": "Fast JSON (C extension, buffer overflow history)"},
    {"name": "orjson", "repo": "ijl/orjson", "category": "serialization", "monthly_downloads": "25M+", "reason": "Fast JSON in Rust"},
    {"name": "msgpack", "repo": "msgpack/msgpack-python", "category": "serialization", "monthly_downloads": "15M+", "reason": "Binary serialization"},
    {"name": "cbor2", "repo": "agronholm/cbor2", "category": "serialization", "monthly_downloads": "5M+", "reason": "CBOR serialization"},

    # --- Cryptography/Security ---
    {"name": "cryptography", "repo": "pyca/cryptography", "category": "crypto", "monthly_downloads": "100M+", "reason": "Core crypto library"},
    {"name": "pyjwt", "repo": "jpadilla/pyjwt", "category": "auth", "monthly_downloads": "50M+", "reason": "JWT implementation (auth bypass history)"},
    {"name": "python-jose", "repo": "mpdavis/python-jose", "category": "auth", "monthly_downloads": "10M+", "reason": "JOSE/JWT/JWS"},
    {"name": "itsdangerous", "repo": "pallets/itsdangerous", "category": "crypto", "monthly_downloads": "40M+", "reason": "Data signing (Flask sessions)"},
    {"name": "paramiko", "repo": "paramiko/paramiko", "category": "crypto", "monthly_downloads": "20M+", "reason": "SSH implementation"},
    {"name": "bcrypt", "repo": "pyca/bcrypt", "category": "crypto", "monthly_downloads": "15M+", "reason": "Password hashing"},
    {"name": "passlib", "repo": "glic3rern/passlib", "category": "auth", "monthly_downloads": "5M+", "reason": "Password hashing framework"},

    # --- Web Frameworks (small/focused) ---
    {"name": "flask", "repo": "pallets/flask", "category": "web", "monthly_downloads": "40M+", "reason": "Micro web framework"},
    {"name": "werkzeug", "repo": "pallets/werkzeug", "category": "web", "monthly_downloads": "40M+", "reason": "WSGI toolkit (path traversal history)"},
    {"name": "jinja2", "repo": "pallets/jinja", "category": "template", "monthly_downloads": "80M+", "reason": "Template engine (SSTI target)"},
    {"name": "starlette", "repo": "encode/starlette", "category": "web", "monthly_downloads": "20M+", "reason": "ASGI framework"},
    {"name": "fastapi", "repo": "fastapi/fastapi", "category": "web", "monthly_downloads": "25M+", "reason": "Modern API framework"},
    {"name": "bottle", "repo": "bottlepy/bottle", "category": "web", "monthly_downloads": "3M+", "reason": "Single-file web framework"},
    {"name": "falcon", "repo": "falconry/falcon", "category": "web", "monthly_downloads": "2M+", "reason": "Minimal REST framework"},

    # --- Input Validation/Parsing ---
    {"name": "pydantic", "repo": "pydantic/pydantic", "category": "validation", "monthly_downloads": "60M+", "reason": "Data validation (ReDoS potential)"},
    {"name": "marshmallow", "repo": "marshmallow-code/marshmallow", "category": "validation", "monthly_downloads": "10M+", "reason": "Object serialization/validation"},
    {"name": "cerberus", "repo": "pyeve/cerberus", "category": "validation", "monthly_downloads": "3M+", "reason": "Schema validation"},
    {"name": "python-multipart", "repo": "Kludex/python-multipart", "category": "parsing", "monthly_downloads": "20M+", "reason": "Multipart form parsing"},
    {"name": "markupsafe", "repo": "pallets/markupsafe", "category": "xss", "monthly_downloads": "80M+", "reason": "HTML escaping (XSS prevention)"},

    # --- File/Path handling ---
    {"name": "pathlib2", "repo": "jazzband/pathlib2", "category": "filesystem", "monthly_downloads": "5M+", "reason": "Path manipulation"},
    {"name": "send2trash", "repo": "arsenetar/send2trash", "category": "filesystem", "monthly_downloads": "10M+", "reason": "File deletion"},
    {"name": "watchdog", "repo": "gorakhargosh/watchdog", "category": "filesystem", "monthly_downloads": "10M+", "reason": "Filesystem monitoring"},
    {"name": "filelock", "repo": "tox-dev/filelock", "category": "filesystem", "monthly_downloads": "80M+", "reason": "File locking (race conditions)"},
    {"name": "platformdirs", "repo": "tox-dev/platformdirs", "category": "filesystem", "monthly_downloads": "80M+", "reason": "Platform-specific dirs"},
    {"name": "appdirs", "repo": "ActiveState/appdirs", "category": "filesystem", "monthly_downloads": "20M+", "reason": "App directories"},

    # --- Database/ORM ---
    {"name": "sqlparse", "repo": "andialbrecht/sqlparse", "category": "database", "monthly_downloads": "20M+", "reason": "SQL parser (injection bypass)"},
    {"name": "peewee", "repo": "coleifer/peewee", "category": "database", "monthly_downloads": "3M+", "reason": "Lightweight ORM"},
    {"name": "dataset", "repo": "pudo/dataset", "category": "database", "monthly_downloads": "500K+", "reason": "Simple DB toolkit"},
    {"name": "tinydb", "repo": "msiemens/tinydb", "category": "database", "monthly_downloads": "1M+", "reason": "Lightweight document DB"},

    # --- CLI/Process ---
    {"name": "click", "repo": "pallets/click", "category": "cli", "monthly_downloads": "60M+", "reason": "CLI framework"},
    {"name": "typer", "repo": "fastapi/typer", "category": "cli", "monthly_downloads": "10M+", "reason": "CLI with type hints"},
    {"name": "sh", "repo": "amoffat/sh", "category": "process", "monthly_downloads": "5M+", "reason": "Subprocess wrapper (injection risk)"},
    {"name": "plumbum", "repo": "tomerfiliba/plumbum", "category": "process", "monthly_downloads": "2M+", "reason": "Shell combinators"},
    {"name": "pexpect", "repo": "pexpect/pexpect", "category": "process", "monthly_downloads": "10M+", "reason": "Process interaction"},

    # --- Networking ---
    {"name": "websockets", "repo": "python-websockets/websockets", "category": "network", "monthly_downloads": "15M+", "reason": "WebSocket library"},
    {"name": "python-socketio", "repo": "miguelgrinberg/python-socketio", "category": "network", "monthly_downloads": "5M+", "reason": "Socket.IO"},
    {"name": "dnspython", "repo": "rthalley/dnspython", "category": "network", "monthly_downloads": "20M+", "reason": "DNS toolkit"},
    {"name": "scapy", "repo": "secdev/scapy", "category": "network", "monthly_downloads": "3M+", "reason": "Packet manipulation"},

    # --- Image/Media ---
    {"name": "pillow", "repo": "python-pillow/Pillow", "category": "media", "monthly_downloads": "50M+", "reason": "Image processing (buffer overflow history)"},
    {"name": "python-magic", "repo": "ahupp/python-magic", "category": "media", "monthly_downloads": "5M+", "reason": "File type detection"},
    {"name": "filetype", "repo": "h2non/filetype.py", "category": "media", "monthly_downloads": "10M+", "reason": "File type identification"},

    # --- Configuration ---
    {"name": "python-dotenv", "repo": "theskumar/python-dotenv", "category": "config", "monthly_downloads": "30M+", "reason": ".env file loading"},
    {"name": "configparser", "repo": "jaraco/configparser", "category": "config", "monthly_downloads": "10M+", "reason": "INI file parser"},
    {"name": "dynaconf", "repo": "dynaconf/dynaconf", "category": "config", "monthly_downloads": "2M+", "reason": "Settings management"},

    # --- Templating/Markup ---
    {"name": "markdown", "repo": "Python-Markdown/markdown", "category": "markup", "monthly_downloads": "10M+", "reason": "Markdown parser (XSS potential)"},
    {"name": "bleach", "repo": "mozilla/bleach", "category": "sanitization", "monthly_downloads": "10M+", "reason": "HTML sanitizer (bypass history)"},
    {"name": "html5lib", "repo": "html5lib/html5lib-python", "category": "parsing", "monthly_downloads": "15M+", "reason": "HTML parser"},
    {"name": "lxml", "repo": "lxml/lxml", "category": "parsing", "monthly_downloads": "30M+", "reason": "XML/HTML (XXE potential)"},
    {"name": "defusedxml", "repo": "tiran/defusedxml", "category": "parsing", "monthly_downloads": "15M+", "reason": "Safe XML parsing"},

    # --- Auth/Session ---
    {"name": "oauthlib", "repo": "oauthlib/oauthlib", "category": "auth", "monthly_downloads": "15M+", "reason": "OAuth implementation"},
    {"name": "authlib", "repo": "lepture/authlib", "category": "auth", "monthly_downloads": "5M+", "reason": "OAuth/OIDC library"},
    {"name": "flask-login", "repo": "maxcountryman/flask-login", "category": "auth", "monthly_downloads": "5M+", "reason": "Flask authentication"},
    {"name": "flask-jwt-extended", "repo": "vimalloc/flask-jwt-extended", "category": "auth", "monthly_downloads": "3M+", "reason": "Flask JWT auth"},

    # --- URL/Email handling ---
    {"name": "furl", "repo": "gruns/furl", "category": "url", "monthly_downloads": "2M+", "reason": "URL manipulation (SSRF potential)"},
    {"name": "validators", "repo": "python-validators/validators", "category": "validation", "monthly_downloads": "5M+", "reason": "Data validators (bypass potential)"},
    {"name": "email-validator", "repo": "JoshData/python-email-validator", "category": "validation", "monthly_downloads": "5M+", "reason": "Email validation"},

    # --- Compression/Archive ---
    {"name": "zipfile36", "repo": "back-to/zipfile36", "category": "archive", "monthly_downloads": "1M+", "reason": "ZIP handling (zip slip)"},
    {"name": "python-zipstream", "repo": "allanlei/python-zipstream", "category": "archive", "monthly_downloads": "500K+", "reason": "Streaming ZIP"},
    {"name": "rarfile", "repo": "markokr/rarfile", "category": "archive", "monthly_downloads": "1M+", "reason": "RAR extraction (path traversal)"},
    {"name": "py7zr", "repo": "miurahr/py7zr", "category": "archive", "monthly_downloads": "2M+", "reason": "7z archive handling"},

    # --- Logging/Monitoring ---
    {"name": "loguru", "repo": "Delgan/loguru", "category": "logging", "monthly_downloads": "10M+", "reason": "Logging library"},
    {"name": "structlog", "repo": "hynek/structlog", "category": "logging", "monthly_downloads": "5M+", "reason": "Structured logging"},
    {"name": "sentry-sdk", "repo": "getsentry/sentry-python", "category": "monitoring", "monthly_downloads": "15M+", "reason": "Error tracking (data leak potential)"},

    # --- Task/Async ---
    {"name": "celery", "repo": "celery/celery", "category": "task", "monthly_downloads": "10M+", "reason": "Task queue (deserialization)"},
    {"name": "rq", "repo": "rq/rq", "category": "task", "monthly_downloads": "3M+", "reason": "Simple job queue"},
    {"name": "apscheduler", "repo": "agronholm/apscheduler", "category": "task", "monthly_downloads": "5M+", "reason": "Task scheduling"},

    # --- Data handling ---
    {"name": "python-dateutil", "repo": "dateutil/dateutil", "category": "data", "monthly_downloads": "100M+", "reason": "Date parsing"},
    {"name": "arrow", "repo": "arrow-py/arrow", "category": "data", "monthly_downloads": "10M+", "reason": "Date/time library"},
    {"name": "humanize", "repo": "python-humanize/humanize", "category": "data", "monthly_downloads": "10M+", "reason": "Human-readable data"},
    {"name": "tabulate", "repo": "astanin/python-tabulate", "category": "data", "monthly_downloads": "20M+", "reason": "Table formatting"},

    # --- Template/Code generation ---
    {"name": "mako", "repo": "sqlalchemy/mako", "category": "template", "monthly_downloads": "10M+", "reason": "Template engine (code exec)"},
    {"name": "chevron", "repo": "noahmorrison/chevron", "category": "template", "monthly_downloads": "2M+", "reason": "Mustache templates"},

    # --- HTTP servers/middleware ---
    {"name": "gunicorn", "repo": "benoitc/gunicorn", "category": "server", "monthly_downloads": "15M+", "reason": "WSGI HTTP server"},
    {"name": "uvicorn", "repo": "encode/uvicorn", "category": "server", "monthly_downloads": "15M+", "reason": "ASGI server"},
    {"name": "waitress", "repo": "Pylons/waitress", "category": "server", "monthly_downloads": "5M+", "reason": "WSGI server (request smuggling)"},
    {"name": "python-multipart", "repo": "Kludex/python-multipart", "category": "parsing", "monthly_downloads": "20M+", "reason": "Multipart parsing"},

    # --- Misc high-value targets ---
    {"name": "pip", "repo": "pypa/pip", "category": "packaging", "monthly_downloads": "200M+", "reason": "Package installer (supply chain)"},
    {"name": "setuptools", "repo": "pypa/setuptools", "category": "packaging", "monthly_downloads": "200M+", "reason": "Build system (code exec in setup.py)"},
    {"name": "wheel", "repo": "pypa/wheel", "category": "packaging", "monthly_downloads": "150M+", "reason": "Wheel format (zip handling)"},
    {"name": "virtualenv", "repo": "pypa/virtualenv", "category": "packaging", "monthly_downloads": "50M+", "reason": "Virtual environments"},
    {"name": "tox", "repo": "tox-dev/tox", "category": "testing", "monthly_downloads": "10M+", "reason": "Test automation"},
    {"name": "invoke", "repo": "pyinvoke/invoke", "category": "process", "monthly_downloads": "5M+", "reason": "Task execution (command injection)"},
    {"name": "fabric", "repo": "fabric/fabric", "category": "process", "monthly_downloads": "3M+", "reason": "Remote execution"},
]


def list_repos(category: Optional[str] = None) -> None:
    """Print the target repository list."""
    repos = TARGET_REPOSITORIES
    if category:
        repos = [r for r in repos if r["category"] == category]

    print(f"\n{'#':<4} {'Name':<25} {'Category':<15} {'Downloads':<12} {'Reason'}")
    print("-" * 100)
    for i, repo in enumerate(repos, 1):
        print(f"{i:<4} {repo['name']:<25} {repo['category']:<15} {repo['monthly_downloads']:<12} {repo['reason']}")
    print(f"\nTotal: {len(repos)} repositories")
    
    categories = sorted(set(r["category"] for r in TARGET_REPOSITORIES))
    print(f"Categories: {', '.join(categories)}")


def download_repo(repo_info: Dict, shallow: bool = True) -> Optional[str]:
    """Clone a repository to the target_repos directory."""
    os.makedirs(REPOS_DIR, exist_ok=True)
    
    repo_path = os.path.join(REPOS_DIR, repo_info["name"])
    if os.path.isdir(repo_path):
        logger.info(f"Repository {repo_info['name']} already exists at {repo_path}")
        return repo_path

    url = f"https://github.com/{repo_info['repo']}.git"
    cmd = ["git", "clone"]
    if shallow:
        cmd.extend(["--depth", "1"])
    cmd.extend([url, repo_path])

    logger.info(f"Cloning {repo_info['name']} from {url}...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        logger.error(f"Failed to clone {repo_info['name']}: {result.stderr}")
        return None
    
    logger.info(f"Cloned {repo_info['name']} to {repo_path}")
    return repo_path


def download_top_n(n: int, category: Optional[str] = None, shallow: bool = True) -> List[str]:
    """Download the top N repositories."""
    repos = TARGET_REPOSITORIES
    if category:
        repos = [r for r in repos if r["category"] == category]
    
    repos = repos[:n]
    paths = []
    
    for repo_info in repos:
        path = download_repo(repo_info, shallow=shallow)
        if path:
            paths.append(path)
    
    return paths


def get_python_files(repo_path: str, exclude_tests: bool = True) -> List[str]:
    """Get all Python files in a repository, optionally excluding test files."""
    py_files = []
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden dirs, __pycache__, venv, etc.
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                   ('__pycache__', 'venv', '.venv', 'node_modules', '.git', 'docs')]
        
        if exclude_tests:
            dirs[:] = [d for d in dirs if d not in ('tests', 'test', 'testing')]
        
        for f in files:
            if f.endswith('.py'):
                if exclude_tests and (f.startswith('test_') or f.endswith('_test.py') or f == 'conftest.py'):
                    continue
                py_files.append(os.path.join(root, f))
    
    return py_files


def analyze_repo_surface(repo_path: str) -> Dict:
    """Analyze a repository's attack surface for prioritization."""
    py_files = get_python_files(repo_path)
    
    # Keywords that indicate security-sensitive code
    security_keywords = {
        "input_handling": ["request", "input", "argv", "stdin", "form", "query", "param"],
        "file_ops": ["open(", "os.path", "shutil", "pathlib", "tempfile", "glob"],
        "network": ["socket", "urllib", "requests", "http", "ssl", "connect"],
        "crypto": ["hash", "encrypt", "decrypt", "sign", "verify", "hmac", "token"],
        "serialization": ["pickle", "yaml", "json.loads", "marshal", "shelve", "eval(", "exec("],
        "subprocess": ["subprocess", "os.system", "os.popen", "Popen", "shell=True"],
        "sql": ["execute(", "cursor", "SELECT", "INSERT", "query"],
        "auth": ["password", "credential", "session", "cookie", "jwt", "oauth", "login"],
    }
    
    surface = {cat: [] for cat in security_keywords}
    total_loc = 0
    
    for filepath in py_files:
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                total_loc += len(lines)
                
                for category, keywords in security_keywords.items():
                    for keyword in keywords:
                        if keyword.lower() in content.lower():
                            rel_path = os.path.relpath(filepath, repo_path)
                            if rel_path not in surface[category]:
                                surface[category].append(rel_path)
                            break
        except Exception:
            continue
    
    return {
        "total_files": len(py_files),
        "total_loc": total_loc,
        "attack_surface": {k: v for k, v in surface.items() if v},
    }


def prepare_scan_input(repo_path: str, output_dir: str = None) -> str:
    """
    Prepare a repository for VAITP scanning by extracting security-relevant
    Python files into a scan input directory.
    """
    if output_dir is None:
        repo_name = os.path.basename(repo_path)
        output_dir = os.path.join(REPOS_DIR, f"{repo_name}_scan_input")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Analyze attack surface
    surface = analyze_repo_surface(repo_path)
    
    # Collect all security-relevant files
    relevant_files = set()
    for category, files in surface["attack_surface"].items():
        relevant_files.update(files)
    
    # Copy relevant files to scan input directory
    import shutil
    copied = 0
    for rel_path in relevant_files:
        src = os.path.join(repo_path, rel_path)
        # Flatten the path for VAITP input (replace / with __)
        flat_name = rel_path.replace(os.sep, "__")
        dst = os.path.join(output_dir, flat_name)
        if os.path.isfile(src):
            shutil.copy2(src, dst)
            copied += 1
    
    logger.info(f"Prepared {copied} files for scanning in {output_dir}")
    
    # Save analysis metadata
    meta_path = os.path.join(output_dir, "_scan_metadata.json")
    with open(meta_path, 'w') as f:
        json.dump({
            "repo_path": repo_path,
            "repo_name": os.path.basename(repo_path),
            "analysis": surface,
            "files_prepared": copied,
        }, f, indent=2)
    
    return output_dir


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    parser = argparse.ArgumentParser(description="VAITP Repository Scanner")
    parser.add_argument("--list", action="store_true", help="List target repositories")
    parser.add_argument("--category", type=str, default=None, help="Filter by category")
    parser.add_argument("--download", type=int, default=None, help="Download top N repositories")
    parser.add_argument("--analyze", type=str, default=None, help="Analyze a repo's attack surface")
    parser.add_argument("--prepare", type=str, default=None, help="Prepare a repo for VAITP scanning")
    parser.add_argument("--full-clone", action="store_true", help="Full clone instead of shallow")
    
    args = parser.parse_args()
    
    if args.list:
        list_repos(category=args.category)
    elif args.download is not None:
        paths = download_top_n(args.download, category=args.category, shallow=not args.full_clone)
        print(f"\nDownloaded {len(paths)} repositories to {REPOS_DIR}")
    elif args.analyze:
        surface = analyze_repo_surface(args.analyze)
        print(json.dumps(surface, indent=2))
    elif args.prepare:
        output = prepare_scan_input(args.prepare)
        print(f"\nScan input prepared at: {output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
