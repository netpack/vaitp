"""
VAITP Phase 0: Zero-Day Discovery Agent

A multi-stage reasoning pipeline that takes a git repository as input and
autonomously identifies potential zero-day vulnerabilities through:

1. Attack Surface Mapping — AST-based identification of security-relevant patterns
2. Hypothesis Generation — LLM-driven "what could go wrong?" reasoning
3. Behavioral Testing — Generate and execute targeted test scripts
4. Cross-Reference — Compare with known-good implementations
5. Severity Assessment — Classify findings by exploitability

This module is designed to be self-improving: each confirmed finding feeds back
into the RAG database, improving future discovery runs.

Usage:
    from orchestration.discovery_agent import DiscoveryAgent
    agent = DiscoveryAgent(repo_path="/path/to/target", llm_fn=ollama_generate)
    findings = agent.run()
"""

import ast
import os
import sys
import json
import time
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class VulnCategory(str, Enum):
    """Categories of vulnerabilities the discovery agent looks for."""
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    AUTH_BYPASS = "auth_bypass"
    ALGORITHMIC_DOS = "algorithmic_dos"
    SSRF = "ssrf"
    CRYPTO_WEAKNESS = "crypto_weakness"
    INPUT_VALIDATION = "input_validation"
    SYMLINK_FOLLOWING = "symlink_following"
    OPEN_REDIRECT = "open_redirect"


@dataclass
class AttackSurface:
    """Represents a security-relevant code location."""
    file_path: str
    function_name: str
    line_number: int
    category: VulnCategory
    pattern_description: str
    code_snippet: str
    confidence: float  # 0.0 - 1.0


@dataclass
class Hypothesis:
    """A vulnerability hypothesis to test."""
    surface: AttackSurface
    description: str
    test_strategy: str  # "behavioral", "comparison", "fuzzing"
    test_code: str  # Python code to verify the hypothesis
    expected_behavior: str
    vulnerable_behavior: str


@dataclass
class Finding:
    """A confirmed or suspected vulnerability."""
    title: str
    category: VulnCategory
    severity: str  # "critical", "high", "medium", "low"
    cwe: str
    description: str
    proof_of_concept: str
    affected_file: str
    affected_function: str
    test_results: Dict[str, Any]
    confirmed: bool
    confidence: float


# ============================================================
# STAGE 1: Attack Surface Mapping
# ============================================================

# Patterns that indicate security-relevant code
SECURITY_PATTERNS = {
    VulnCategory.DESERIALIZATION: {
        "imports": ["pickle", "yaml", "marshal", "shelve", "jsonpickle", "dill"],
        "calls": ["loads", "load", "unsafe_load", "full_load", "deserialize",
                  "unmarshal", "from_dict", "from_json", "decode"],
        "keywords": ["serializ", "marshal", "deserializ", "unmarshal"],
    },
    VulnCategory.PATH_TRAVERSAL: {
        "imports": ["zipfile", "tarfile", "rarfile", "py7zr", "shutil"],
        "calls": ["extractall", "extract", "open", "symlink", "makedirs",
                  "copyfile", "move", "rename"],
        "keywords": ["extract", "archive", "unzip", "untar", "decompress"],
    },
    VulnCategory.COMMAND_INJECTION: {
        "imports": ["subprocess", "os", "shlex", "pty"],
        "calls": ["system", "popen", "Popen", "call", "check_output",
                  "run", "exec", "spawn", "execvp"],
        "keywords": ["shell=True", "command", "execute"],
    },
    VulnCategory.AUTH_BYPASS: {
        "imports": ["jwt", "jose", "authlib", "oauthlib", "itsdangerous"],
        "calls": ["decode", "verify", "validate", "authenticate",
                  "check_password", "compare_digest"],
        "keywords": ["audience", "issuer", "algorithm", "signature", "token"],
    },
    VulnCategory.ALGORITHMIC_DOS: {
        "imports": ["re", "regex"],
        "calls": ["compile", "match", "search", "findall", "parse",
                  "loads", "parse_declaration_list"],
        "keywords": ["recursion", "nested", "depth", "backtrack"],
    },
    VulnCategory.SSRF: {
        "imports": ["requests", "urllib", "httpx", "aiohttp"],
        "calls": ["get", "post", "request", "urlopen", "fetch"],
        "keywords": ["url", "redirect", "proxy", "forward"],
    },
    VulnCategory.CRYPTO_WEAKNESS: {
        "imports": ["hashlib", "hmac", "cryptography", "Crypto"],
        "calls": ["md5", "sha1", "new", "compare_digest", "pbkdf2_hmac"],
        "keywords": ["hash", "encrypt", "decrypt", "sign", "verify", "key"],
    },
    VulnCategory.SYMLINK_FOLLOWING: {
        "imports": ["os", "pathlib", "shutil"],
        "calls": ["symlink", "readlink", "realpath", "resolve",
                  "is_symlink", "symlink_to"],
        "keywords": ["symlink", "link", "junction"],
    },
}

# Hypothesis templates for each category
HYPOTHESIS_TEMPLATES = {
    VulnCategory.AUTH_BYPASS: [
        "What happens when a required claim ({claim}) is missing from the token?",
        "Can the algorithm be confused by providing a different key type?",
        "Is the signature verification timing-safe?",
        "What happens with an empty or None value for the {param} parameter?",
        "If the caller specifies audience/issuer, are tokens WITHOUT that claim rejected?",
        "Can a token signed with algorithm 'none' bypass verification?",
        "Does the library enforce that claims specified by the caller must be present in the token?",
    ],
    VulnCategory.ALGORITHMIC_DOS: [
        "What is the time complexity when input has {n} repeated elements?",
        "Does deeply nested input cause stack overflow or excessive CPU?",
        "Is there quadratic behavior when many items share a common prefix?",
        "Can a small input (<10KB) cause >1 second of processing?",
        "Does parsing time grow linearly or super-linearly with input size?",
        "Are there O(n²) loops when merging/inserting into internal data structures?",
    ],
    VulnCategory.PATH_TRAVERSAL: [
        "Is the symlink target validated against the extraction directory?",
        "Can path components with '..' escape the target directory?",
        "Are Windows device names (CON, NUL) handled on all platforms?",
        "What happens with encoded path separators (%2F, %5C)?",
    ],
    VulnCategory.DESERIALIZATION: [
        "Can arbitrary classes be instantiated during deserialization?",
        "Is there an allowlist for deserializable types?",
        "Can the type/class reference be controlled by the input?",
        "Does the deserializer call __setstate__ or __reduce__ on untrusted data?",
    ],
    VulnCategory.COMMAND_INJECTION: [
        "Is user input passed to shell commands without escaping?",
        "Can shell metacharacters (;|&$`) break out of the intended command?",
        "Is shell=True used with variable input?",
    ],
}


def map_attack_surface(repo_path: str, exclude_tests: bool = True) -> List[AttackSurface]:
    """
    Stage 1: Walk the repository and identify security-relevant code locations
    using AST analysis.
    """
    surfaces = []
    repo = Path(repo_path)

    for py_file in repo.rglob("*.py"):
        # Skip test files, docs, venvs
        rel_path = str(py_file.relative_to(repo))
        if exclude_tests and any(skip in rel_path for skip in
                                  ["test", "docs", "venv", ".venv", "__pycache__",
                                   "node_modules", ".git", "examples", "benchmarks"]):
            continue

        try:
            source = py_file.read_text(errors="ignore")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        # Collect imports and function calls
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])

        # Check each category
        for category, patterns in SECURITY_PATTERNS.items():
            # Check imports
            matching_imports = imports & set(patterns["imports"])
            if not matching_imports:
                continue

            # Find relevant functions
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_source = ast.get_source_segment(source, node)
                    if not func_source:
                        continue

                    # Check for relevant calls within the function
                    has_relevant_call = False
                    for call_node in ast.walk(node):
                        if isinstance(call_node, ast.Call):
                            call_name = ""
                            if isinstance(call_node.func, ast.Name):
                                call_name = call_node.func.id
                            elif isinstance(call_node.func, ast.Attribute):
                                call_name = call_node.func.attr

                            if call_name.lower() in [c.lower() for c in patterns["calls"]]:
                                has_relevant_call = True
                                break

                    if has_relevant_call:
                        # Calculate confidence based on keyword matches
                        keyword_matches = sum(
                            1 for kw in patterns["keywords"]
                            if kw.lower() in func_source.lower()
                        )
                        confidence = min(0.3 + keyword_matches * 0.2, 0.95)

                        surfaces.append(AttackSurface(
                            file_path=rel_path,
                            function_name=node.name,
                            line_number=node.lineno,
                            category=category,
                            pattern_description=f"Uses {matching_imports} with calls to security-relevant functions",
                            code_snippet=func_source[:500],
                            confidence=confidence,
                        ))

    # Sort by confidence (highest first)
    surfaces.sort(key=lambda s: s.confidence, reverse=True)
    return surfaces


# ============================================================
# STAGE 2: Hypothesis Generation (LLM-driven)
# ============================================================

HYPOTHESIS_SYSTEM_PROMPT = """You are a security researcher analyzing Python code for zero-day vulnerabilities.
Given a code snippet and its security category, generate a specific, testable hypothesis
about what could go wrong. Focus on:
- Missing validation or sanitization
- Insecure defaults that developers might not notice
- Algorithmic complexity issues with crafted input
- Logic errors in security-critical paths
- Differences from reference implementations

Respond with a JSON object:
{
  "hypothesis": "One sentence describing what might be vulnerable",
  "test_strategy": "behavioral|comparison|fuzzing",
  "test_code": "Python code that tests the hypothesis (must be self-contained, print VULNERABLE or SAFE)",
  "expected_safe_behavior": "What should happen if the code is secure",
  "vulnerable_behavior": "What happens if the vulnerability exists"
}"""


def generate_hypotheses(
    surfaces: List[AttackSurface],
    llm_fn: Callable[[str], str],
    max_hypotheses: int = 10,
) -> List[Hypothesis]:
    """
    Stage 2: Use the LLM to generate testable vulnerability hypotheses
    for the top attack surfaces.
    """
    hypotheses = []

    for surface in surfaces[:max_hypotheses]:
        prompt = f"""{HYPOTHESIS_SYSTEM_PROMPT}

Category: {surface.category.value}
File: {surface.file_path}
Function: {surface.function_name} (line {surface.line_number})
Code:
```python
{surface.code_snippet}
```

Generate a testable vulnerability hypothesis for this code."""

        try:
            response = llm_fn(prompt, max_tokens=2048)
            # Parse JSON from response
            parsed = _extract_json(response)
            if parsed:
                hypotheses.append(Hypothesis(
                    surface=surface,
                    description=parsed.get("hypothesis", ""),
                    test_strategy=parsed.get("test_strategy", "behavioral"),
                    test_code=parsed.get("test_code", ""),
                    expected_behavior=parsed.get("expected_safe_behavior", ""),
                    vulnerable_behavior=parsed.get("vulnerable_behavior", ""),
                ))
        except Exception as e:
            logger.warning(f"Hypothesis generation failed for {surface.file_path}:{surface.function_name}: {e}")

    return hypotheses


# ============================================================
# STAGE 3: Dynamic Testing
# ============================================================

# Built-in test generators for common vulnerability patterns.
# These don't need the LLM — they generate deterministic tests
# based on the attack surface category.

BUILTIN_TESTS = {
    VulnCategory.ALGORITHMIC_DOS: """
import sys
import time
sys.path.insert(0, "{repo_path}")

# Test for quadratic/cubic complexity by measuring parsing time
# at different input sizes and checking if growth is super-linear.
try:
    import {module_name}
except ImportError:
    print("SAFE: module not importable")
    sys.exit(0)

# Generate inputs of increasing size with shared-prefix pattern
def gen_input(n):
    # Dotted keys with shared prefix (common DoS pattern)
    return "\\n".join([f"a.b.c.key{{i}} = {{i}}" for i in range(n)])

times = []
for n in [5, 10, 20, 40]:
    payload = gen_input(n)
    start = time.time()
    try:
        {module_name}.parse(payload) if hasattr({module_name}, 'parse') else {module_name}.loads(payload)
    except Exception:
        pass
    elapsed = time.time() - start
    times.append((n, elapsed))

# Check for super-linear growth
if len(times) >= 3 and times[0][1] > 0:
    ratio = times[-1][1] / times[0][1]
    size_ratio = times[-1][0] / times[0][0]
    # If time grows more than 3x what linear would predict, it's suspicious
    if ratio > size_ratio * 3:
        print(f"VULNERABLE: Super-linear complexity detected. "
              f"Size ratio={{size_ratio:.1f}}x, time ratio={{ratio:.1f}}x")
    else:
        print(f"SAFE: Linear or sub-linear growth. "
              f"Size ratio={{size_ratio:.1f}}x, time ratio={{ratio:.1f}}x")
else:
    print("SAFE: Could not measure timing")
""",

    VulnCategory.AUTH_BYPASS: """
import sys
sys.path.insert(0, "{repo_path}")

# Test: Does specifying audience/issuer reject tokens missing that claim?
try:
    from {module_name} import jwt
except ImportError:
    try:
        import {module_name}
        jwt = {module_name}
    except ImportError:
        print("SAFE: module not importable")
        sys.exit(0)

# Try to find the decode function
decode_fn = None
if hasattr(jwt, 'decode'):
    decode_fn = jwt.decode
elif hasattr(jwt, 'JWT'):
    decode_fn = jwt.JWT().decode

if decode_fn is None:
    print("SAFE: No decode function found")
    sys.exit(0)

# Create a token WITHOUT audience claim
secret = "test-secret-key-12345"
try:
    if hasattr(jwt, 'encode'):
        token = jwt.encode({{"sub": "test"}}, secret, algorithm="HS256")
    else:
        print("SAFE: No encode function")
        sys.exit(0)
except Exception as e:
    print(f"SAFE: encode failed: {{e}}")
    sys.exit(0)

# Try to decode with audience specified — should this be rejected?
try:
    result = decode_fn(token, secret, algorithms=["HS256"], audience="expected-service")
    # If we get here, the token was ACCEPTED despite missing 'aud'
    print(f"VULNERABLE: Token without 'aud' claim accepted when audience='expected-service' was specified. "
          f"Decoded: {{result}}")
except TypeError:
    # audience parameter not supported — not this type of library
    print("SAFE: audience parameter not supported")
except Exception as e:
    # Token was rejected — correct behavior
    print(f"SAFE: Token correctly rejected: {{e}}")
""",
}


def generate_builtin_test(category: VulnCategory, repo_path: str, module_name: str) -> Optional[str]:
    """Generate a built-in test for the given category without needing the LLM."""
    template = BUILTIN_TESTS.get(category)
    if not template:
        return None
    return template.format(repo_path=repo_path, module_name=module_name)


def _detect_module_name(repo_path: str) -> str:
    """Detect the importable module name from a repository."""
    repo = Path(repo_path)
    # Look for src/<name>/ or <name>/ with __init__.py
    for candidate in repo.iterdir():
        if candidate.is_dir() and (candidate / "__init__.py").exists():
            if candidate.name not in ("tests", "test", "docs", "examples", ".git"):
                return candidate.name
    # Check src/ directory
    src = repo / "src"
    if src.is_dir():
        for candidate in src.iterdir():
            if candidate.is_dir() and (candidate / "__init__.py").exists():
                return candidate.name
    # Fallback: repo name
    return repo.name.replace("-", "_")


def test_hypothesis(
    hypothesis: Hypothesis,
    repo_path: str,
    python_path: str = sys.executable,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Stage 3: Execute the test code and determine if the vulnerability exists.
    Returns test results including timing, output, and verdict.
    """
    if not hypothesis.test_code:
        return {"verdict": "SKIP", "reason": "No test code generated"}

    # Write test to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        # Prepend the repo path to sys.path
        f.write(f"import sys; sys.path.insert(0, {repr(repo_path)})\n")
        f.write(hypothesis.test_code)
        test_file = f.name

    try:
        start = time.time()
        result = subprocess.run(
            [python_path, test_file],
            capture_output=True, text=True, timeout=timeout,
            cwd=repo_path,
        )
        elapsed = time.time() - start

        output = result.stdout + result.stderr
        is_vulnerable = "VULNERABLE" in output.upper()
        is_timeout = False

        return {
            "verdict": "VULNERABLE" if is_vulnerable else "SAFE",
            "output": output[:2000],
            "returncode": result.returncode,
            "elapsed_s": elapsed,
            "timed_out": False,
        }

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return {
            "verdict": "TIMEOUT",
            "output": "Test exceeded timeout — possible DoS",
            "elapsed_s": elapsed,
            "timed_out": True,
        }
    except Exception as e:
        return {
            "verdict": "ERROR",
            "output": str(e),
            "elapsed_s": 0,
            "timed_out": False,
        }
    finally:
        os.unlink(test_file)


# ============================================================
# STAGE 4: Severity Assessment (LLM-driven)
# ============================================================

SEVERITY_SYSTEM_PROMPT = """You are a security researcher assessing a potential vulnerability finding.
Given the test results, determine:
1. Is this a real vulnerability or a false positive?
2. What is the severity (critical/high/medium/low)?
3. What CWE applies?
4. Is this likely to get a CVE assigned?

Consider:
- Does it require special prerequisites (auth, network access, etc.)?
- Is it a design choice documented by the maintainer?
- How many users/applications are affected?
- Is there a reference implementation that handles this correctly?

Respond with JSON:
{
  "is_vulnerability": true/false,
  "severity": "critical|high|medium|low",
  "cwe": "CWE-XXX",
  "cve_likelihood": "high|medium|low",
  "reasoning": "Brief explanation",
  "recommended_action": "disclose|report_as_bug|document_only|false_positive"
}"""


# ============================================================
# MAIN DISCOVERY AGENT
# ============================================================

class DiscoveryAgent:
    """
    Orchestrates the full zero-day discovery pipeline.

    Usage:
        agent = DiscoveryAgent(
            repo_path="/path/to/target",
            llm_fn=my_ollama_generate_function,
        )
        findings = agent.run()
    """

    def __init__(
        self,
        repo_path: str,
        llm_fn: Callable[[str], str],
        python_path: str = sys.executable,
        max_surfaces: int = 20,
        max_hypotheses: int = 10,
        test_timeout: int = 30,
        skip_builtin: bool = False,
    ):
        self.repo_path = os.path.abspath(repo_path)
        self.llm_fn = llm_fn
        self.python_path = python_path
        self.max_surfaces = max_surfaces
        self.max_hypotheses = max_hypotheses
        self.test_timeout = test_timeout
        self.skip_builtin = skip_builtin
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        """Execute the full discovery pipeline."""
        logger.info(f"Starting discovery on: {self.repo_path}")

        # Stage 1: Map attack surface
        logger.info("Stage 1: Mapping attack surface...")
        surfaces = map_attack_surface(self.repo_path)
        logger.info(f"  Found {len(surfaces)} security-relevant locations")

        # Detect module name for imports
        module_name = _detect_module_name(self.repo_path)
        logger.info(f"  Detected module: {module_name}")

        # Stage 2a: Run built-in tests (no LLM needed, fast)
        if not self.skip_builtin:
            logger.info("Stage 2a: Running built-in vulnerability checks...")
            categories_seen = set()
            for surface in surfaces[:self.max_surfaces]:
                if surface.category in categories_seen:
                    continue
                categories_seen.add(surface.category)

                test_code = generate_builtin_test(surface.category, self.repo_path, module_name)
            if test_code:
                logger.info(f"  Testing [{surface.category.value}] with built-in check...")
                builtin_hyp = Hypothesis(
                    surface=surface,
                    description=f"Built-in {surface.category.value} check for {module_name}",
                    test_strategy="behavioral",
                    test_code=test_code,
                    expected_behavior="SAFE",
                    vulnerable_behavior="VULNERABLE or TIMEOUT",
                )
                results = test_hypothesis(
                    builtin_hyp, self.repo_path,
                    python_path=self.python_path,
                    timeout=self.test_timeout,
                )
                if results["verdict"] in ("VULNERABLE", "TIMEOUT"):
                    finding = Finding(
                        title=f"Built-in check: {surface.category.value} in {module_name}",
                        category=surface.category,
                        severity="medium",
                        cwe=self._cwe_for_category(surface.category),
                        description=results.get("output", "")[:500],
                        proof_of_concept=test_code,
                        affected_file=surface.file_path,
                        affected_function=surface.function_name,
                        test_results=results,
                        confirmed=(results["verdict"] == "VULNERABLE"),
                        confidence=0.9 if results["verdict"] == "VULNERABLE" else 0.7,
                    )
                    self.findings.append(finding)
                    logger.info(f"    → {results['verdict']}! {results.get('output', '')[:100]}")
                else:
                    logger.info(f"    → {results['verdict']}")

        # Stage 2b: Generate LLM hypotheses for surfaces not caught by built-in tests
        logger.info("Stage 2b: Generating LLM vulnerability hypotheses...")
        hypotheses = generate_hypotheses(
            surfaces[:self.max_surfaces],
            self.llm_fn,
            max_hypotheses=self.max_hypotheses,
        )
        logger.info(f"  Generated {len(hypotheses)} testable hypotheses")

        # Stage 3: Test LLM hypotheses
        logger.info("Stage 3: Testing LLM hypotheses dynamically...")
        for i, hypothesis in enumerate(hypotheses, 1):
            logger.info(f"  [{i}/{len(hypotheses)}] Testing: {hypothesis.description[:80]}")
            results = test_hypothesis(
                hypothesis, self.repo_path,
                python_path=self.python_path,
                timeout=self.test_timeout,
            )

            if results["verdict"] in ("VULNERABLE", "TIMEOUT"):
                finding = Finding(
                    title=hypothesis.description,
                    category=hypothesis.surface.category,
                    severity="medium",
                    cwe=self._cwe_for_category(hypothesis.surface.category),
                    description=hypothesis.description,
                    proof_of_concept=hypothesis.test_code,
                    affected_file=hypothesis.surface.file_path,
                    affected_function=hypothesis.surface.function_name,
                    test_results=results,
                    confirmed=(results["verdict"] == "VULNERABLE"),
                    confidence=hypothesis.surface.confidence,
                )
                self.findings.append(finding)
                logger.info(f"    → {results['verdict']}!")

        logger.info(f"Discovery complete: {len(self.findings)} potential findings")
        return self.findings

    @staticmethod
    def _cwe_for_category(category: VulnCategory) -> str:
        """Map category to most common CWE."""
        return {
            VulnCategory.AUTH_BYPASS: "CWE-287",
            VulnCategory.ALGORITHMIC_DOS: "CWE-400",
            VulnCategory.PATH_TRAVERSAL: "CWE-22",
            VulnCategory.COMMAND_INJECTION: "CWE-78",
            VulnCategory.DESERIALIZATION: "CWE-502",
            VulnCategory.SSRF: "CWE-918",
            VulnCategory.CRYPTO_WEAKNESS: "CWE-327",
            VulnCategory.SYMLINK_FOLLOWING: "CWE-59",
            VulnCategory.INPUT_VALIDATION: "CWE-20",
            VulnCategory.OPEN_REDIRECT: "CWE-601",
        }.get(category, "")

    def save_results(self, output_path: str = "results/discovery_findings.json"):
        """Save findings to JSON."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump([asdict(f) for f in self.findings], f, indent=2, default=str)
        logger.info(f"Results saved to: {output_path}")


# ============================================================
# HELPERS
# ============================================================

def _extract_json(text: str) -> Optional[Dict]:
    """Extract JSON from LLM response."""
    import re
    # Try to find JSON block
    json_match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    # Try the whole text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
