"""
VAITP Phase 3: Formal Data Contracts
Strict schema definitions for SEP, CEP, AEP, FEP, and verification results.
All LLM-generated plans must conform to these dataclasses.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class Strategy(str, Enum):
    STDIO = "stdio"
    NETWORK = "network"


class VerificationState(str, Enum):
    """The four states of the Double-Check Truth Table."""
    VULN_BENIGN_OK = "vuln_benign_ok"          # Vuln + Benign -> Success
    VULN_MALICIOUS_EXPLOITED = "vuln_exploited" # Vuln + Malicious -> Exploited
    PATCH_BENIGN_OK = "patch_benign_ok"         # Patch + Benign -> Success
    PATCH_MALICIOUS_BLOCKED = "patch_blocked"   # Patch + Malicious -> Blocked


class TestVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    INFRA_FAILURE = "INFRA_FAILURE"


# ==========================================
# File Mapping (for legacy compatibility)
# ==========================================
@dataclass
class FileMapping:
    source_path: str
    destination_path: str
    type: str  # 'vulnerable' or 'patched'


# ==========================================
# SEP: Setup Execution Plan
# ==========================================
@dataclass
class ServiceDefinition:
    """A sidecar container (e.g., MongoDB, MySQL)."""
    image: str                          # e.g. "mongo:4.4"
    alias: str                          # Network alias, e.g. "mongodb"
    ports: Dict[str, int] = field(default_factory=dict)
    environment: Dict[str, str] = field(default_factory=dict)
    health_check_cmd: Optional[str] = None
    startup_delay: int = 5


@dataclass
class SEP:
    """Setup Execution Plan: Defines the infrastructure for a test."""
    target_id: str                      # CVE or CWE identifier
    image: str                          # Base Docker image
    working_dir: str                    # Container working directory
    dependencies: List[str]             # e.g. ["git", "pip:flask"]
    setup_commands: List[str] = field(default_factory=list)
    services: List[Dict[str, str]] = field(default_factory=list)
    ready_signal: Optional[str] = None
    files: List[FileMapping] = field(default_factory=list)
    execution_context: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> 'SEP':
        return cls(
            target_id=data.get("target_id", "unknown"),
            image=data.get("image", "python:3.9-slim"),
            working_dir=data.get("working_dir", "/app"),
            dependencies=data.get("dependencies", []),
            setup_commands=data.get("setup_commands", []),
            services=data.get("services", []),
            ready_signal=data.get("ready_signal"),
        )


# ==========================================
# CEP: Common Execution Plan
# ==========================================
@dataclass
class CEP:
    """Common Execution Plan: Shared delivery mechanism for both AEP and FEP.
    Holds the strategy, network config, and success criteria that are common
    to both functional and exploit checks.
    """
    success_file: str                   # File to check for side-effect, e.g. "/tmp/pwned"
    strategy: str = "stdio"             # "stdio" or "network"
    target_url: str = ""                # For network strategy
    http_method: str = "GET"            # GET or POST
    json_template: Optional[str] = None # e.g. '{"domain": "netpack.pt%s"}'
    multipart_filename: Optional[str] = None  # For file upload attacks
    http_headers: Optional[Dict[str, str]] = None  # e.g. {"Cookie": "auth=PAYLOAD_PLACEHOLDER"}
    exploit_rationale: str = ""         # Human-readable explanation of the exploit
    side_effect_hook: Optional[str] = None  # Python code snippet injected into vuln code at runtime
                                            # to create success_file when the vulnerability triggers.
                                            # Format: "FIND_LINE|||REPLACE_WITH" where FIND_LINE is a
                                            # substring of a line in the vuln code, and REPLACE_WITH is
                                            # the replacement code (may be multi-line with \n).

    @classmethod
    def from_dict(cls, data: dict) -> 'CEP':
        # LLMs sometimes output json_template as a JSON object (dict) instead of
        # a string with a %s placeholder. Coerce to JSON string so downstream
        # code (.find(), [:80], %s substitution) works correctly.
        jt = data.get("json_template")
        if isinstance(jt, dict):
            import json as _json
            jt = _json.dumps(jt)
        return cls(
            success_file=data.get("success_file", "/tmp/pwned"),
            strategy=data.get("strategy", "stdio"),
            target_url=data.get("target_url", ""),
            http_method=data.get("http_method", "GET"),
            json_template=jt,
            multipart_filename=data.get("multipart_filename"),
            http_headers=data.get("http_headers"),
            exploit_rationale=data.get("exploit_rationale", ""),
            side_effect_hook=data.get("side_effect_hook"),
        )


# ==========================================
# AEP: Attack Execution Plan
# ==========================================
def _normalize_aep_try(t: dict) -> dict:
    """Normalize an AEP try so downstream code can assume string payloads.

    LLMs sometimes emit a structured object (dict/list) for the "input" or
    "generator" field instead of a string. Slicing or hashing those raises
    TypeError deep in the pipeline. We coerce non-string scalars to str and
    dict/list to a JSON string (preserving the intended payload content).
    """
    t = dict(t)
    for key in ("input", "generator"):
        if key in t and t[key] is not None and not isinstance(t[key], str):
            v = t[key]
            if isinstance(v, (dict, list)):
                import json as _json
                try:
                    t[key] = _json.dumps(v)
                except Exception:
                    t[key] = str(v)
            else:
                t[key] = str(v)
    return t


@dataclass
class AEP:
    """Attack Execution Plan: Defines the malicious payloads to test.

      - input (str):          The payload string. For simple attacks, this IS the payload.
      - response (str|None):  Expected response substring (None for exploit checks).
      - generator (str|None): Python script that GENERATES the payload at runtime.
                               Runs inside the container, stdout becomes the actual payload.
                               Use for complex binary payloads (pickle, zip, custom formats).
      - craft_file (dict|None): A file to write into the container BEFORE running the exploit.
                                 {"path": "/app/evil.xml", "content": "..."} for inline content,
                                 or {"path": "/app/evil.bin", "generator": "..."} for dynamic.
                                 The input field then references this file path.

    Any single successful try proves the vulnerability.
    """
    tries: List[Dict[str, Optional[str]]]  # [{"input": "...", "response": None, ...}, ...]

    @classmethod
    def from_dict(cls, data: dict) -> 'AEP':
        tries = data.get("tries", [])
        if not tries:
            tries = [{"input": "", "response": None}]
        tries = [_normalize_aep_try(t) for t in tries if isinstance(t, dict)]
        if not tries:
            tries = [{"input": "", "response": None}]
        return cls(tries=tries)


# ==========================================
# FEP: Functional Execution Plan
# ==========================================
@dataclass
class FEP:
    """Functional Execution Plan: Defines the benign verification data.
    Each try is {"input": str, "response": str}.
    ALL tries must pass to consider the functional check successful.

    patch_tries: Optional separate tries for the patched code. Used when the
    vuln and patch accept different input formats (e.g., pickle vs JSON
    deserialization). If not set, the regular tries are used for both.
    """
    tries: List[Dict[str, str]]  # [{"input": "...", "response": "..."}, ...]
    patch_tries: Optional[List[Dict[str, str]]] = None  # Optional separate tries for patch

    @classmethod
    def from_dict(cls, data: dict) -> 'FEP':
        tries = data.get("tries", [])
        if not tries:
            tries = [{"input": "", "response": ""}]
        patch_tries = data.get("patch_tries")
        return cls(tries=tries, patch_tries=patch_tries)


# ==========================================
# Attack Results
# ==========================================
@dataclass
class AttackResult:
    """The outcome of a single attack step."""
    payload_id: str
    success: bool
    logs: str
    side_effects: Dict[str, bool] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class FunctionalResult:
    """Result of a functional (benign) check."""
    script_name: str
    passed: bool
    output: str
    expected: str
    error: Optional[str] = None


@dataclass
class ExploitResult:
    """Result of a security (exploit) check."""
    script_name: str
    exploited: bool
    success_file: str
    output: str
    error: Optional[str] = None


# ==========================================
# Verification Report (Truth Table)
# ==========================================
@dataclass
class VerificationReport:
    """
    The Double-Check Methodology result.
    A test PASSES only when all four states match the truth table:
      Vuln + Benign    -> Success (functional)
      Vuln + Malicious -> Exploited (side-effect detected)
      Patch + Benign   -> Success (functional)
      Patch + Malicious-> Blocked (no side-effect)
    """
    test_name: str
    sep: SEP
    cep: CEP
    aep: AEP
    fep: FEP = None
    # Functional checks
    vuln_functional: FunctionalResult = None
    patch_functional: FunctionalResult = None
    # Security checks
    vuln_exploit: ExploitResult = None
    patch_exploit: ExploitResult = None
    # Timing
    provision_time: float = 0.0
    functional_time: float = 0.0
    security_time: float = 0.0
    # Verdict
    verdict: TestVerdict = TestVerdict.ERROR
    failure_reasons: List[str] = field(default_factory=list)
    iteration: int = 0

    def evaluate(self) -> 'VerificationReport':
        """Apply the Truth Table to determine the verdict."""
        self.failure_reasons = []

        if self.vuln_functional and not self.vuln_functional.passed:
            self.failure_reasons.append("Vuln Broken (benign input failed)")
        if self.patch_functional and not self.patch_functional.passed:
            self.failure_reasons.append("Patch Broken (benign input failed)")

        if self.vuln_exploit and not self.vuln_exploit.exploited:
            self.failure_reasons.append("Vuln Safe (exploit did not trigger)")
        if self.patch_exploit and self.patch_exploit.exploited:
            self.failure_reasons.append("Patch Bypassed (exploit succeeded on patched code)")

        if not self.failure_reasons:
            self.verdict = TestVerdict.PASS
        elif any("Broken" in r for r in self.failure_reasons):
            self.verdict = TestVerdict.INFRA_FAILURE
        else:
            self.verdict = TestVerdict.FAIL

        return self

    @property
    def passed(self) -> bool:
        return self.verdict == TestVerdict.PASS

    @property
    def total_time(self) -> float:
        return self.provision_time + self.functional_time + self.security_time


# ==========================================
# Planner Feedback (for self-correction loop)
# ==========================================
@dataclass
class PlannerFeedback:
    """Feedback sent back to the Planner Agent for self-correction."""
    iteration: int
    report: VerificationReport
    suggestion: str

    @classmethod
    def from_report(cls, report: VerificationReport, iteration: int,
                    llm_generate_fn=None, vuln_code: str = "",
                    patch_code: str = "") -> 'PlannerFeedback':
        """Generate feedback from a verification report.

        If an LLM function is provided, generates a context-aware diagnostic
        prompt based on the actual failure data. Otherwise falls back to
        static rule-based suggestions.
        """
        # Try LLM-generated feedback first for richer, context-aware suggestions
        if llm_generate_fn and vuln_code:
            try:
                llm_suggestion = cls._generate_llm_feedback(
                    report, vuln_code, patch_code, llm_generate_fn
                )
                if llm_suggestion:
                    return cls(
                        iteration=iteration,
                        report=report,
                        suggestion=llm_suggestion,
                    )
            except Exception:
                pass  # Fall through to static feedback

        # Static fallback
        suggestions = []
        for reason in report.failure_reasons:
            if "Broken" in reason:
                # Extract specific error details from functional check output
                vuln_output = getattr(report.vuln_functional, 'output', '') or ''
                patch_output = getattr(report.patch_functional, 'output', '') or ''
                combined = vuln_output + patch_output
                import re as _re
                missing_import = _re.search(r"name '(\w+)' is not defined", combined)
                if missing_import:
                    suggestions.append(
                        f"The code is missing 'import {missing_import.group(1)}'. "
                        f"Add it to the imports or dependencies."
                    )
                elif "IndentationError" in combined:
                    suggestions.append(
                        "The code has indentation errors. Fix the whitespace."
                    )
                elif "500" in combined and "Traceback" in combined:
                    suggestions.append(
                        "The Flask app returns 500 on benign input. Check that all "
                        "routes handle the expected input format correctly. "
                        "Review the traceback for the specific error."
                    )
                else:
                    suggestions.append(
                        "Fix the environment: check dependencies, setup_commands, or benign input. "
                        "The application does not run correctly with benign input."
                    )
            elif "Vuln Safe" in reason:
                suggestions.append(
                    "Fix the exploit payload (aep tries). The malicious input did not create "
                    f"the expected side-effect file at {report.cep.success_file}. "
                    "IMPORTANT: Do NOT change the vulnerability type or CWE category. "
                    "Keep targeting the SAME vulnerability. "
                    "Consider: is the payload reaching the vulnerable sink? "
                    "Check encoding (Base64 for CLI, URL encoding for network), "
                    "and verify the payload format matches what the code expects."
                )
            elif "Patch Bypassed" in reason:
                suggestions.append(
                    "The patch is ineffective OR the payload is too generic. "
                    "Verify the patched code actually fixes the vulnerability."
                )
        return cls(
            iteration=iteration,
            report=report,
            suggestion=" | ".join(suggestions) if suggestions else "Unknown failure mode.",
        )

    @staticmethod
    def _generate_llm_feedback(report: 'VerificationReport', vuln_code: str,
                                patch_code: str, llm_generate_fn) -> str:
        """Use the LLM to generate context-aware diagnostic feedback.

        Includes static code analysis hints so the LLM can reason about
        shell quoting, SQL methods, false positives, etc.
        """
        import json as _json

        failure_context = []
        if report.vuln_functional and not report.vuln_functional.passed:
            failure_context.append(
                f"Vuln functional FAILED. Output: {report.vuln_functional.output[:300]}\n"
                f"Expected: {report.vuln_functional.expected}"
            )
        if report.patch_functional and not report.patch_functional.passed:
            failure_context.append(
                f"Patch functional FAILED. Output: {report.patch_functional.output[:300]}\n"
                f"Expected: {report.patch_functional.expected}"
            )
        if report.vuln_exploit and not report.vuln_exploit.exploited:
            failure_context.append(
                f"Vuln exploit FAILED (no file created at {report.cep.success_file}). "
                f"Output: {report.vuln_exploit.output[:300]}"
            )
        if report.patch_exploit and report.patch_exploit.exploited:
            failure_context.append(
                f"Patch exploit SUCCEEDED (should have been blocked). "
                f"Output: {report.patch_exploit.output[:300]}"
            )

        # Include code analysis hints for richer feedback
        code_hints_section = ""
        try:
            from orchestration.planner_agent import analyze_code_for_plan_hints
            hints = analyze_code_for_plan_hints(vuln_code, patch_code)
            if hints:
                code_hints_section = f"\nCode analysis hints:\n{hints}\n"
        except ImportError:
            pass

        prompt = (
            "You are debugging a vulnerability test failure. Analyze the failure data "
            "and provide a CONCISE, ACTIONABLE suggestion (2-3 sentences max) for fixing "
            "the test plan. Focus on the root cause and what specifically needs to change.\n\n"
            f"Test: {report.test_name}\n"
            f"Failures: {', '.join(report.failure_reasons)}\n"
            f"Strategy: {report.cep.strategy}\n"
            f"Success file: {report.cep.success_file}\n\n"
            f"Failure details:\n" + "\n".join(failure_context) + "\n\n"
            f"{code_hints_section}"
            f"Vuln code (first 500 chars):\n{vuln_code[:500]}\n\n"
            "Respond with ONLY the suggestion text, no JSON or formatting."
        )

        raw = llm_generate_fn(prompt, 1024)
        # Strip any <think> blocks from reasoning models
        import re as _re
        cleaned = _re.sub(r'<think>.*?</think>', '', raw, flags=_re.DOTALL).strip()
        return cleaned[:1500] if cleaned else None
