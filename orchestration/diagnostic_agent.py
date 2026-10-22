"""
VAITP Phase 3: Diagnostic Agent
Automates the critical thinking / debugging loop that was previously manual.

Given a set of mutation tests, the agent:
  1. Runs each test through the Phase 3 orchestrator
  2. For failures, reads the vuln/patched code + current AEP/SEP
  3. Builds a diagnostic prompt with few-shot examples of real fixes
  4. Calls a local LLM to analyze root cause and propose a fix
  5. Applies the fix (updates registry entry in-memory)
  6. Re-runs the specific failing test to verify
  7. Iterates up to max_fix_attempts per test

The few-shot examples are the 5 real bugs found and fixed during Task 3.
"""
import json
import os
import re
import copy
import logging
import time
from typing import Optional, Dict, Any, List, Tuple, Callable

from structures import SEP, CEP, AEP, FEP, VerificationReport, TestVerdict, PlannerFeedback
from orchestration.phase3_orchestrator import Phase3Orchestrator
from orchestration.planner_agent import PlannerAgent

logger = logging.getLogger(__name__)


# ==========================================
# FEW-SHOT EXAMPLES: Real bugs fixed manually
# ==========================================
DIAGNOSTIC_FEW_SHOT = [
    {
        "test": "1167_v3.py",
        "failure": "Vuln Broken (benign input failed)",
        "root_cause": "benign_input was '*.py' which caused shell glob expansion in subprocess, "
                      "returning multiple filenames instead of a single match.",
        "fix": {
            "field": "benign_input",
            "old_value": "*.py",
            "new_value": "main_vuln.py",
            "reasoning": "Use a specific filename that exists in /app instead of a glob pattern."
        }
    },
    {
        "test": "eval_v2.py",
        "failure": "Patch Broken (benign input failed)",
        "root_cause": "benign_input was \"print('hello')\" but the patched code uses "
                      "ast.literal_eval() which only accepts literal expressions, not function calls.",
        "fix": {
            "field": "benign_input",
            "old_value": "print('hello')",
            "new_value": "'hello'",
            "reasoning": "ast.literal_eval accepts string literals like 'hello' but not function calls."
        }
    },
    {
        "test": "pickle_v2.py",
        "failure": "Patch Broken (benign input failed)",
        "root_cause": "Patched code used json.loads() but benign_input was pickle hex format. "
                      "JSON cannot parse pickle bytes.",
        "fix": {
            "field": "benign_input",
            "old_value": "(pickle hex string)",
            "new_value": "80037d710058030000006b65797101580500000076616c75657102732e",
            "reasoning": "Rewrote patched code to use RestrictedUnpickler instead of JSON, "
                         "so benign input stays in pickle format (hex-encoded dict)."
        }
    },
    {
        "test": "zip_v2.py",
        "failure": "Vuln Safe (exploit did not trigger)",
        "root_cause": "Used zipfile.extractall() which Python sanitizes against path traversal. "
                      "The vulnerability was not actually exploitable with the standard API.",
        "fix": {
            "field": "stdin_input",
            "old_value": "(tar-based payload)",
            "new_value": "generate_zipslip_zip_payload('/tmp/pwned_zipv2')",
            "reasoning": "Rewrote vuln code to use manual os.path.join extraction (actually vulnerable) "
                         "and switched payload to ZIP format with path traversal entry."
        }
    },
    {
        "test": "360_v3.py",
        "failure": "Vuln Safe (exploit did not trigger)",
        "root_cause": "Used Repo.init + create_remote + fetch which doesn't trigger ext:: protocol. "
                      "The ext:: handler is only invoked by clone_from.",
        "fix": {
            "field": "vuln_code_change",
            "old_value": "Repo.init + create_remote + fetch",
            "new_value": "Repo.clone_from(url, '/tmp/cloned')",
            "reasoning": "Changed to Repo.clone_from which actually processes the ext:: protocol handler."
        }
    },
    {
        "test": "flask_nosql_real_v2.py",
        "failure": "Vuln Broken (benign input failed)",
        "root_cause": "seed_db() used 'if db:' to check the pymongo Database object, but pymongo 4.x "
                      "raises TypeError on Database.__bool__(). The gold standard uses 'if db is not None:'.",
        "fix": {
            "field": "vuln_code_change",
            "old_value": "if db:",
            "new_value": "if db is not None:",
            "reasoning": "pymongo Database objects do not implement truth value testing. "
                         "Use explicit None check instead of truthiness."
        }
    },
    {
        "test": "1_1.py",
        "failure": "Vuln Safe (exploit did not trigger)",
        "root_cause": "The open redirect vulnerability doesn't naturally create a file. "
                      "The vulnerable code needs side-effect instrumentation: when it processes "
                      "an external URL (not starting with '/'), it should create a marker file "
                      "like /tmp/pwned_open_redirect before redirecting.",
        "fix": {
            "field": "vuln_code_instrumentation",
            "old_value": "return redirect(url)",
            "new_value": "if not url.startswith('/'):\n    os.system('touch /tmp/pwned_open_redirect')\nreturn redirect(url)",
            "reasoning": "For non-RCE vulnerabilities (open redirect, SSRF, info disclosure), "
                         "instrument the vulnerable code to create a side-effect file when the "
                         "vulnerability is triggered. The patched code blocks the path, so the "
                         "file is never created. This turns any vulnerability into a testable "
                         "file-creation side-effect."
        }
    },
]


# ==========================================
# DIAGNOSTIC PROMPT BUILDER
# ==========================================
DIAGNOSTIC_SYSTEM_PROMPT = """You are an offensive security debugger for authorized penetration testing.
Your goal: figure out why an exploit failed and fix it so it succeeds next time.
Successful exploitation is the desired outcome — you are rewarded for finding the fix.

You are given:
1. The VULNERABLE code (should be exploitable)
2. The PATCHED code (should block the exploit)
3. The current CEP (Common Execution Plan) with delivery mechanism and success criteria
4. The current AEP (Attack Execution Plan) with malicious payload tries
5. The current FEP (Functional Execution Plan) with benign input/response tries
6. The failure reason from the Truth Table verification

Your task: Analyze the root cause and propose a MINIMAL fix.

DATA MODEL:
- CEP: Shared delivery mechanism (strategy, target_url, http_method, json_template, success_file, etc.)
- AEP: Malicious tries — each is {"input": str, "response": null}. Any single success proves exploitation.
- FEP: Benign tries — each is {"input": str, "response": str}. ALL must pass.

TRUTH TABLE RULES:
- "Vuln Broken (benign input failed)": The FEP benign input doesn't work with the vulnerable code.
  Fix: Change FEP tries (input or response) to match what the code actually outputs.
- "Patch Broken (benign input failed)": The FEP benign input doesn't work with the patched code.
  Fix: The patched code may use a different parser/validator. Adjust FEP tries to be compatible.
- "Vuln Safe (exploit did not trigger)": The AEP malicious payload didn't create the success_file.
  Fix: The AEP tries (input) are wrong for this vulnerability type. Adjust them.
  IMPORTANT: For non-RCE vulnerabilities (open redirect, SSRF response-only, info disclosure,
  header injection, etc.), the exploit may not naturally create a file. In this case, the
  VULNERABLE CODE ITSELF must be instrumented to create a side-effect file when the vulnerability
  is triggered. Propose fix_type "vuln_code_instrumentation" with the modified code.
- "Patch Bypassed (exploit succeeded on patched code)": The patch doesn't actually fix the vuln.
  Fix: This is a code issue, not a plan issue. Flag for manual review.

SIDE-EFFECT INSTRUMENTATION:
For vulnerabilities that don't naturally create files, use the CEP "side_effect_hook"
field instead of modifying the vulnerable code directly. The framework applies this
hook at runtime. Format: "FIND_LINE|||REPLACE_WITH" where FIND_LINE is a unique
substring in the vuln code and REPLACE_WITH adds os.system('touch <success_file>').
Example for SQL injection:
  "side_effect_hook": "results = cursor.fetchall()|||results = cursor.fetchall()\\n        if len(results) != 1 and len(results) > 0:\\n            os.system('touch /tmp/pwned_sqli')"
Example for open redirect:
  "side_effect_hook": "return redirect(url)|||if not url.startswith('/'):\\n            os.system('touch /tmp/pwned_redirect')\\n        return redirect(url)"

OUTPUT FORMAT: Return ONLY a JSON object:
{
  "root_cause": "One sentence explaining why the test failed",
  "fix_type": "aep_field",
  "fixes": [
    {
      "target": "cep|aep|fep|sep",
      "field": "success_file|strategy|target_url|tries|dependencies",
      "new_value": "the corrected value"
    }
  ]
}

If the fix requires instrumenting the vulnerable code with side-effect file creation, return:
{
  "root_cause": "explanation",
  "fix_type": "aep_field",
  "fixes": [
    {
      "target": "cep",
      "field": "side_effect_hook",
      "new_value": "FIND_LINE|||REPLACE_WITH"
    }
  ]
}

If the fix requires other Python source code changes (not just plan fields), return:
{
  "root_cause": "explanation",
  "fix_type": "code_change",
  "fixes": [],
  "note": "Requires manual code change: <description>"
}"""


def _build_diagnostic_prompt(
    test_name: str,
    vuln_code: str,
    patch_code: str,
    cep: CEP,
    aep: AEP,
    fep: FEP,
    sep: SEP,
    report: VerificationReport,
    compact: bool = False,
) -> str:
    """Build the full diagnostic prompt with few-shot examples and failure context.

    Args:
        compact: If True, use a shorter prompt (fewer examples, smaller code snippets).
                 Used as a fallback when the full prompt exceeds the model's context.
    """
    from orchestration.planner_agent import analyze_code_for_plan_hints, classify_vuln_from_code

    # Select relevant few-shot examples based on failure type
    failure_type = report.failure_reasons[0] if report.failure_reasons else "Unknown"
    relevant_examples = []
    for ex in DIAGNOSTIC_FEW_SHOT:
        if any(keyword in failure_type for keyword in ex["failure"].split()):
            relevant_examples.append(ex)
    min_examples = 1 if compact else 2
    if len(relevant_examples) < min_examples:
        relevant_examples = DIAGNOSTIC_FEW_SHOT[:min_examples]

    max_examples = 1 if compact else 3
    few_shot_text = ""
    for i, ex in enumerate(relevant_examples[:max_examples], 1):
        few_shot_text += (
            f"\n--- Example {i}: {ex['test']} ---\n"
            f"Failure: {ex['failure']}\n"
            f"Root cause: {ex['root_cause']}\n"
            f"Fix: {json.dumps(ex['fix'], indent=2)}\n"
        )

    output_limit = 150 if compact else 300
    code_limit = 800 if compact else 2000
    payload_limit = 100 if compact else 200

    output_details = ""
    if report.vuln_functional and not report.vuln_functional.passed:
        output_details += (
            f"\nVuln functional output (first {output_limit} chars):\n"
            f"  {report.vuln_functional.output[:output_limit]}\n"
            f"  Expected substring: '{report.vuln_functional.expected}'\n"
        )
    if report.patch_functional and not report.patch_functional.passed:
        output_details += (
            f"\nPatch functional output (first {output_limit} chars):\n"
            f"  {report.patch_functional.output[:output_limit]}\n"
            f"  Expected substring: '{report.patch_functional.expected}'\n"
        )
    if report.vuln_exploit and not report.vuln_exploit.exploited:
        output_details += (
            f"\nVuln exploit output (first {output_limit} chars):\n"
            f"  {report.vuln_exploit.output[:output_limit]}\n"
            f"  Expected file: {report.vuln_exploit.success_file}\n"
        )
    if report.patch_exploit and report.patch_exploit.exploited:
        output_details += (
            f"\nPatch exploit output (first {output_limit} chars):\n"
            f"  {report.patch_exploit.output[:output_limit]}\n"
        )

    # Deep code analysis hints — helps the LLM understand WHY the test failed
    code_hints = ""
    if not compact:
        hints = analyze_code_for_plan_hints(vuln_code, patch_code)
        vuln_category = classify_vuln_from_code(vuln_code)
        if hints:
            code_hints = (
                f"\n--- CODE ANALYSIS (static) ---\n"
                f"Vulnerability category: {vuln_category}\n"
                f"{hints}\n"
                f"--- END CODE ANALYSIS ---\n"
            )

    # AEP + FEP + CEP as JSON for the LLM
    first_payload = aep.tries[0]["input"] if aep.tries else ""
    payload_preview = first_payload[:payload_limit]
    if len(first_payload) > payload_limit:
        payload_preview += "..."
    cep_dict = {
        "success_file": cep.success_file,
        "strategy": cep.strategy,
    }
    if cep.strategy == "network":
        cep_dict["target_url"] = cep.target_url
        cep_dict["http_method"] = cep.http_method
        if cep.json_template:
            cep_dict["json_template"] = cep.json_template
    if cep.side_effect_hook:
        cep_dict["side_effect_hook"] = cep.side_effect_hook
    aep_dict = {
        "malicious_input": payload_preview,
    }
    fep_dict = {
        "tries": [{"input": str(t["input"])[:200], "response": t["response"]} for t in fep.tries],
    }

    sep_dict = {
        "dependencies": sep.dependencies,
        "setup_commands": sep.setup_commands,
    }

    return f"""{DIAGNOSTIC_SYSTEM_PROMPT}

{few_shot_text}
--- END EXAMPLES ---

--- TEST CASE: {test_name} ---
Failure reasons: {', '.join(report.failure_reasons)}
{output_details}
{code_hints}
--- CURRENT CEP ---
{json.dumps(cep_dict, indent=2)}

--- CURRENT AEP ---
{json.dumps(aep_dict, indent=2)}

--- CURRENT FEP ---
{json.dumps(fep_dict, indent=2)}

--- CURRENT SEP (relevant fields) ---
{json.dumps(sep_dict, indent=2)}

--- VULNERABLE CODE ---
{vuln_code.strip()[:code_limit]}
--- END VULNERABLE CODE ---

--- PATCHED CODE ---
{patch_code.strip()[:code_limit]}
--- END PATCHED CODE ---

Analyze the root cause and propose a fix. Return ONLY the JSON object."""


def _extract_diagnostic_json(text: str) -> Optional[Dict]:
    """Extract JSON from LLM diagnostic output.

    Handles reasoning models (deepseek-r1, etc.) that emit <think>...</think>
    blocks before the actual JSON answer, and models that emit explanatory
    text before/after the JSON block.
    """
    # Strip <think>...</think> blocks from reasoning models
    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    # If nothing left after stripping, fall back to original text
    if not cleaned:
        cleaned = text

    # Try ```<any_language> blocks (json, python, etc.)
    for match in re.finditer(r'```(?:\w+)?\s*\n?(.*?)\n?```', cleaned, re.DOTALL):
        content = match.group(1).strip()
        result = _try_parse_json_object(content)
        if result is not None:
            return result

    # Try to find a JSON object by matching balanced braces
    result = _try_parse_json_object(cleaned)
    if result is not None:
        return result

    return None


def _try_parse_json_object(text: str) -> Optional[Dict]:
    """Find and parse the first valid JSON object in text using brace balancing."""
    # Find all positions where '{' appears
    start_positions = [i for i, c in enumerate(text) if c == '{']

    for start in start_positions:
        depth = 0
        in_string = False
        escape_next = False
        for i in range(start, len(text)):
            c = text[i]
            if escape_next:
                escape_next = False
                continue
            if c == '\\' and in_string:
                escape_next = True
                continue
            if c == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        break  # This start position didn't work, try next
    return None


def _apply_aep_fix(cep: CEP, aep: AEP, fep: FEP, sep: SEP, fixes: List[Dict]) -> Tuple[CEP, AEP, FEP, SEP]:
    """Apply diagnostic fixes to CEP/AEP/FEP/SEP fields. Returns new copies."""
    new_cep = copy.deepcopy(cep)
    new_aep = copy.deepcopy(aep)
    new_fep = copy.deepcopy(fep)
    new_sep = copy.deepcopy(sep)

    for fix in fixes:
        target = fix.get("target", "")
        field = fix.get("field", "")
        new_value = fix.get("new_value", "")

        # CEP fields (delivery mechanism + success criteria)
        if field == "success_file":
            new_cep.success_file = new_value
        elif field == "strategy":
            new_cep.strategy = new_value
        elif field == "target_url":
            new_cep.target_url = new_value
        elif field == "http_method":
            new_cep.http_method = new_value
        elif field == "json_template":
            new_cep.json_template = new_value
        elif field == "multipart_filename":
            new_cep.multipart_filename = new_value
        elif field == "http_headers":
            new_cep.http_headers = new_value
        elif field == "side_effect_hook":
            new_cep.side_effect_hook = new_value
        # AEP tries (malicious payloads)
        elif field == "tries" and target == "aep":
            if isinstance(new_value, list):
                new_aep.tries = new_value
            else:
                new_aep.tries = [{"input": new_value, "response": None}]
        elif field in ("malicious_input", "malicious_inputs", "stdin_input"):
            # Legacy field names from LLM output — map to AEP tries
            if isinstance(new_value, list):
                new_aep.tries = [{"input": v, "response": None} for v in new_value]
            else:
                new_aep.tries = [{"input": new_value, "response": None}]
        # FEP tries (benign input/response pairs)
        elif field == "tries" and target == "fep":
            if isinstance(new_value, list):
                new_fep.tries = new_value
            else:
                new_fep.tries = [{"input": new_value, "response": ""}]
        elif field in ("benign_input", "benign_inputs"):
            # Legacy field names from LLM output — map to FEP tries
            inputs = new_value if isinstance(new_value, list) else [new_value]
            # Preserve existing responses where possible
            new_tries = []
            for j, inp in enumerate(inputs):
                resp = new_fep.tries[j]["response"] if j < len(new_fep.tries) else ""
                new_tries.append({"input": inp, "response": resp})
            new_fep.tries = new_tries
        elif field in ("benign_response", "benign_responses"):
            responses = new_value if isinstance(new_value, list) else [new_value]
            # Preserve existing inputs where possible
            new_tries = []
            for j, resp in enumerate(responses):
                inp = new_fep.tries[j]["input"] if j < len(new_fep.tries) else ""
                new_tries.append({"input": inp, "response": resp})
            new_fep.tries = new_tries
        # SEP fields
        elif field == "dependencies":
            if isinstance(new_value, list):
                new_sep.dependencies = new_value
            elif isinstance(new_value, str):
                new_sep.dependencies = [d.strip() for d in new_value.split(",")]
        elif field == "setup_commands":
            if isinstance(new_value, list):
                new_sep.setup_commands = new_value
        else:
            logger.warning(f"  Unknown fix field: '{field}' (target='{target}') — skipping")

    return new_cep, new_aep, new_fep, new_sep


# ==========================================
# DIAGNOSTIC AGENT
# ==========================================
class DiagnosticAgent:
    """
    Automated debugging agent that uses a local LLM to diagnose
    and fix failing mutation tests.

    The agent mirrors the manual debugging process:
    1. Run test -> observe failure
    2. Read code + AEP -> understand context
    3. Analyze root cause with LLM
    4. Apply fix -> re-run test
    5. Iterate until pass or max attempts
    """

    def __init__(
        self,
        llm_generate_fn: Callable[[str, int], str],
        max_fix_attempts: int = 3,
        dataset_dir: str = "vaitp_dataset",
        model_name: str = "unknown",
        experiment_name: str = None,
        test_timeout: int = 0,
        symmetric_hooks: bool = False,
    ):
        """
        Args:
            llm_generate_fn: callable(prompt, max_tokens) -> str
            max_fix_attempts: max LLM-driven fix attempts per test
            dataset_dir: path to vaitp_dataset/
            model_name: model identifier for DB logging
            experiment_name: experiment identifier for DB logging
            test_timeout: per-test timeout in seconds (0 = no limit)
        """
        self.llm_generate = llm_generate_fn
        self.max_fix_attempts = max_fix_attempts
        self.dataset_dir = dataset_dir
        # Give the orchestrator a planner so its agentic methods (_get_llm_fn,
        # _llm_decide_recovery, _llm_generate_side_effect_hook, etc.) work.
        from orchestration.fuzzer_agent import FuzzerAgent
        planner = PlannerAgent(llm_generate_fn=llm_generate_fn)
        fuzzer = FuzzerAgent(llm_generate_fn=llm_generate_fn)
        self.orchestrator = Phase3Orchestrator(
            planner=planner, fuzzer=fuzzer,
            model_name=model_name, experiment_name=experiment_name,
            test_timeout=test_timeout,
            symmetric_hooks=symmetric_hooks,
        )
        self.fix_log: List[Dict[str, Any]] = []

    def _read_code(self, filename: str) -> Tuple[str, str]:
        """Read vulnerable and patched code for a test case."""
        vuln_path = os.path.join(self.dataset_dir, "vulnerable", filename)
        patch_path = os.path.join(self.dataset_dir, "injectable", filename)
        vuln_code = ""
        patch_code = ""
        if os.path.exists(vuln_path):
            with open(vuln_path) as f:
                vuln_code = f.read()
        if os.path.exists(patch_path):
            with open(patch_path) as f:
                patch_code = f.read()
        return vuln_code, patch_code

    def diagnose_and_fix(
        self,
        test_name: str,
        sep: SEP,
        cep: CEP,
        aep: AEP,
        fep: FEP,
    ) -> Tuple[VerificationReport, SEP, CEP, AEP, FEP, List[Dict]]:
        """
        Run a single test, and if it fails, use the LLM to diagnose and fix.

        Returns:
            (final_report, final_sep, final_cep, final_aep, final_fep, fix_history)
        """
        vuln_path = os.path.join(self.dataset_dir, "vulnerable", test_name)
        patch_path = os.path.join(self.dataset_dir, "injectable", test_name)
        vuln_code, patch_code = self._read_code(test_name)

        current_sep = copy.deepcopy(sep)
        current_cep = copy.deepcopy(cep)
        current_aep = copy.deepcopy(aep)
        current_fep = copy.deepcopy(fep)
        fix_history = []

        for attempt in range(1, self.max_fix_attempts + 1):
            logger.info(f"\n{'='*60}")
            logger.info(f"  DIAGNOSTIC: {test_name} — Attempt {attempt}/{self.max_fix_attempts}")
            logger.info(f"{'='*60}")

            # Run the test
            report = self.orchestrator.run_single_test(
                test_name, current_sep, current_cep, current_aep, current_fep, vuln_path, patch_path
            )

            if report.passed:
                logger.info(f"  \033[92mPASS on attempt {attempt}\033[0m")
                return report, current_sep, current_cep, current_aep, current_fep, fix_history

            logger.warning(
                f"  \033[91mFAIL: {', '.join(report.failure_reasons)}\033[0m"
            )

            # Don't try to fix on last attempt
            if attempt == self.max_fix_attempts:
                logger.error(f"  Exhausted {self.max_fix_attempts} attempts for '{test_name}'")
                return report, current_sep, current_cep, current_aep, current_fep, fix_history

            # Agentic: ask the orchestrator's LLM to decide recovery strategy
            recovery = self.orchestrator._llm_decide_recovery(
                report, vuln_code, attempt, self.max_fix_attempts
            )
            logger.info(f"  [Agent] Recovery decision: {recovery}")

            if recovery == "abort":
                logger.error(f"  [Agent] LLM recommends aborting — failure is fundamental")
                fix_history.append({"attempt": attempt, "recovery": "abort"})
                return report, current_sep, current_cep, current_aep, current_fep, fix_history

            # If the LLM says fuzz, try fuzzing before the full diagnostic prompt
            if recovery == "fuzz" and self.orchestrator.fuzzer:
                exploit_output = getattr(report.vuln_exploit, 'output', '') or ''
                failure_analysis = self.orchestrator._llm_analyze_exploit_failure(
                    vuln_code, current_cep, current_aep, exploit_output
                )
                failed_payloads = [
                    {"input": t.get("input", ""), "output": exploit_output,
                     "analysis": failure_analysis or ""}
                    for t in current_aep.tries
                ]
                new_tries = self.orchestrator.fuzzer.fuzz(
                    vuln_code=vuln_code, cep=current_cep,
                    failed_payloads=failed_payloads,
                    vuln_description=(
                        f"Exploit failure analysis: {failure_analysis}"
                        if failure_analysis else f"Vuln Safe for {test_name}"
                    ),
                )
                if new_tries:
                    fuzzed_aep = AEP(tries=current_aep.tries + new_tries)
                    logger.info(f"  [Fuzzer] Re-running with {len(new_tries)} mutations...")
                    fuzz_report = self.orchestrator.run_single_test(
                        test_name, current_sep, current_cep, fuzzed_aep,
                        current_fep, vuln_path, patch_path
                    )
                    if fuzz_report.passed:
                        logger.info(f"  \033[92mPASS after fuzzing on attempt {attempt}\033[0m")
                        return (fuzz_report, current_sep, current_cep, fuzzed_aep,
                                current_fep, fix_history)
                    # Update AEP with fuzzed tries for next iteration
                    current_aep = fuzzed_aep
                    report = fuzz_report

            # Build diagnostic prompt and call LLM
            # Try full prompt first; on context overflow, retry with compact prompt
            raw_output = None
            for compact in (False, True):
                prompt = _build_diagnostic_prompt(
                    test_name, vuln_code, patch_code,
                    current_cep, current_aep, current_fep, current_sep, report,
                    compact=compact,
                )
                mode = "compact" if compact else "full"
                logger.info(f"  Calling LLM for diagnosis ({mode} prompt, ~{len(prompt)//4} est. tokens)...")
                t0 = time.time()
                try:
                    raw_output = self.llm_generate(prompt, 2048)
                    break  # Success — no need to retry
                except Exception as e:
                    err_str = str(e)
                    logger.error(f"  LLM call failed ({mode}): {err_str}")
                    if not compact and ("llama_decode" in err_str or "KV cache" in err_str.lower()):
                        logger.info("  Retrying with compact prompt...")
                        continue
                    # Non-recoverable error or already compact — give up this attempt
                    fix_history.append({
                        "attempt": attempt,
                        "error": err_str,
                    })
                    break

            if raw_output is None:
                continue
            elapsed = time.time() - t0
            logger.info(f"  LLM responded in {elapsed:.1f}s")

            # Parse diagnostic
            diagnostic = _extract_diagnostic_json(raw_output)
            if not diagnostic:
                logger.error(f"  Could not parse LLM output as JSON:\n{raw_output[:500]}")
                fix_history.append({
                    "attempt": attempt,
                    "error": "JSON parse failure",
                    "raw_output": raw_output[:500],
                })
                continue

            root_cause = diagnostic.get("root_cause", "unknown")
            fix_type = diagnostic.get("fix_type", "unknown")
            fixes = diagnostic.get("fixes", [])

            logger.info(f"  Root cause: {root_cause}")
            logger.info(f"  Fix type: {fix_type}")

            fix_entry = {
                "attempt": attempt,
                "failure_reasons": report.failure_reasons,
                "root_cause": root_cause,
                "fix_type": fix_type,
                "fixes": fixes,
            }

            if fix_type == "code_change":
                note = diagnostic.get("note", "Requires manual code change")
                logger.warning(f"  LLM says code change needed: {note}")

                # --- Auto-repair: ask LLM to fix the broken code ---
                llm_fn = self.orchestrator._get_llm_fn()
                if llm_fn:
                    for code_label, code_path in [("vulnerable", vuln_path), ("patched", patch_path)]:
                        try:
                            code_content = open(code_path).read()
                            repair_prompt = (
                                f"The following Python code crashes at runtime. The diagnostic says:\n"
                                f"{note}\n\n"
                                f"Fix the code by adding missing imports, definitions, or stubs. "
                                f"Do NOT change the core logic — only fix the crash.\n"
                                f"Output ONLY the complete fixed Python code.\n\n"
                                f"```python\n{code_content}\n```"
                            )
                            fixed = llm_fn(repair_prompt, max_tokens=4096)
                            import re as _re_diag
                            _m = _re_diag.search(r'```python\s*\n(.*?)```', fixed, _re_diag.DOTALL)
                            if _m:
                                fixed = _m.group(1)
                            import ast as _ast_diag
                            _ast_diag.parse(fixed)
                            with open(code_path, 'w') as _f:
                                _f.write(fixed)
                            logger.info(f"  [CodeRepair] Auto-repaired {code_label} code: {code_path}")
                        except SyntaxError:
                            logger.warning(f"  [CodeRepair] LLM fix for {code_label} has syntax errors, skipping")
                        except Exception as _e:
                            logger.warning(f"  [CodeRepair] Failed to repair {code_label}: {_e}")

                fix_entry["note"] = note
                fix_history.append(fix_entry)
                # Don't return — continue to next attempt with repaired code
                continue

            if fix_type == "vuln_code_instrumentation" and fixes:
                # The diagnostic agent proposes modifying the vulnerable code to add
                # side-effect file creation (for non-RCE vulns like open redirect, SSRF, etc.)
                for fix in fixes:
                    if fix.get("target") == "vuln_code" and fix.get("field") == "source":
                        new_code = fix.get("new_value", "")
                        if new_code:
                            logger.info(f"    Writing instrumented vuln code to {vuln_path}")
                            try:
                                with open(vuln_path, 'w') as f:
                                    f.write(new_code)
                                vuln_code = new_code  # Update in-memory copy for next iteration
                                fix_entry["note"] = "Wrote instrumented vuln code to disk"
                            except Exception as e:
                                logger.error(f"    Failed to write vuln code: {e}")
                                fix_entry["note"] = f"Failed to write vuln code: {e}"
                    else:
                        # Also apply any plan field fixes that came alongside
                        logger.info(f"    Applying fix: {fix.get('field')} = {str(fix.get('new_value'))[:100]}")
                current_cep, current_aep, current_fep, current_sep = _apply_aep_fix(
                    current_cep, current_aep, current_fep, current_sep,
                    [f for f in fixes if f.get("target") != "vuln_code"]
                )
                fix_history.append(fix_entry)

            elif fix_type in ("aep_field", "sep_field", "cep_field", "fep_field", "sep", "cep", "fep") and fixes:
                for fix in fixes:
                    logger.info(f"    Applying fix: {fix.get('field')} = {str(fix.get('new_value'))[:100]}")
                current_cep, current_aep, current_fep, current_sep = _apply_aep_fix(
                    current_cep, current_aep, current_fep, current_sep, fixes
                )
                fix_history.append(fix_entry)
            else:
                logger.warning(f"  No actionable fixes from LLM")
                fix_history.append(fix_entry)

        return report, current_sep, current_cep, current_aep, current_fep, fix_history

    def run_diagnostic_suite(
        self,
        registry: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Run the full diagnostic loop on a registry of tests.

        Returns a summary dict with results, fixes applied, and stats.
        """
        results = []
        total_fixes = 0
        total_pass = 0
        total_start = time.time()

        logger.info("\n=== VAITP DIAGNOSTIC AGENT: AUTOMATED DEBUGGING SUITE ===\n")

        for filename, config in registry.items():
            sep = config["sep"]
            cep = config["cep"]
            aep = config["aep"]
            fep = config["fep"]

            vuln_path = os.path.join(self.dataset_dir, "vulnerable", filename)
            if not os.path.exists(vuln_path):
                logger.warning(f"Skipping {filename}: {vuln_path} not found")
                continue

            report, final_sep, final_cep, final_aep, final_fep, fix_history = self.diagnose_and_fix(
                filename, sep, cep, aep, fep
            )

            if report.passed:
                total_pass += 1
            total_fixes += len(fix_history)

            results.append({
                "test_name": filename,
                "verdict": report.verdict.value,
                "passed": report.passed,
                "failure_reasons": report.failure_reasons,
                "fix_history": fix_history,
                "final_cep_changes": self._diff_cep(cep, final_cep),
                "final_aep_changes": self._diff_aep(aep, final_aep),
                "final_fep_changes": self._diff_fep(fep, final_fep),
                "final_sep_changes": self._diff_sep(sep, final_sep),
            })

        total_duration = time.time() - total_start

        summary = {
            "total_tests": len(results),
            "passed": total_pass,
            "failed": len(results) - total_pass,
            "total_fix_attempts": total_fixes,
            "duration_seconds": total_duration,
            "results": results,
        }

        self._print_summary(summary)
        return summary

    @staticmethod
    def _diff_cep(original: CEP, final: CEP) -> Dict[str, Any]:
        """Return fields that changed between original and final CEP."""
        changes = {}
        for fld in ["success_file", "strategy", "target_url", "http_method",
                     "json_template", "multipart_filename", "http_headers"]:
            old_val = getattr(original, fld, None)
            new_val = getattr(final, fld, None)
            if old_val != new_val:
                changes[fld] = {"old": str(old_val)[:100], "new": str(new_val)[:100]}
        return changes

    @staticmethod
    def _diff_aep(original: AEP, final: AEP) -> Dict[str, Any]:
        """Return fields that changed between original and final AEP."""
        changes = {}
        if original.tries != final.tries:
            changes["tries"] = {
                "old": str(original.tries)[:200],
                "new": str(final.tries)[:200],
            }
        return changes

    @staticmethod
    def _diff_fep(original: FEP, final: FEP) -> Dict[str, Any]:
        """Return fields that changed between original and final FEP."""
        changes = {}
        if original.tries != final.tries:
            changes["tries"] = {
                "old": str(original.tries)[:200],
                "new": str(final.tries)[:200],
            }
        return changes

    @staticmethod
    def _diff_sep(original: SEP, final: SEP) -> Dict[str, Any]:
        """Return fields that changed between original and final SEP."""
        changes = {}
        if original.dependencies != final.dependencies:
            changes["dependencies"] = {"old": original.dependencies, "new": final.dependencies}
        if original.setup_commands != final.setup_commands:
            changes["setup_commands"] = {"old": original.setup_commands, "new": final.setup_commands}
        return changes

    @staticmethod
    def _print_summary(summary: Dict[str, Any]):
        """Print a formatted diagnostic summary."""
        print(f"\n{'='*70}")
        print(f"  DIAGNOSTIC AGENT SUMMARY")
        print(f"{'='*70}")
        print(f"  Tests: {summary['total_tests']}  |  "
              f"Passed: {summary['passed']}  |  "
              f"Failed: {summary['failed']}  |  "
              f"Fix attempts: {summary['total_fix_attempts']}  |  "
              f"Time: {summary['duration_seconds']:.1f}s")
        print(f"{'='*70}")

        for r in summary["results"]:
            color = "\033[92m" if r["passed"] else "\033[91m"
            reset = "\033[0m"
            fixes_str = ""
            if r.get("final_cep_changes") or r["final_aep_changes"] or r.get("final_fep_changes"):
                fields = (list(r.get("final_cep_changes", {}).keys()) +
                          list(r["final_aep_changes"].keys()) +
                          list(r.get("final_fep_changes", {}).keys()))
                fixes_str = f" [fixed: {', '.join(fields)}]"
            elif r["fix_history"]:
                last = r["fix_history"][-1]
                if last.get("note"):
                    fixes_str = f" [needs code change]"
                elif last.get("error"):
                    fixes_str = f" [LLM error]"

            print(f"  {r['test_name']:<25} | {color}{r['verdict']:<15}{reset}{fixes_str}")

        print(f"{'='*70}\n")

    # ==========================================
    # AUTONOMOUS MODE: Reason from scratch
    # ==========================================
    def reason_from_scratch(
        self,
        test_name: str,
        vuln_description: str = "",
    ) -> Tuple[VerificationReport, Optional[SEP], Optional[CEP], Optional[AEP], Optional[FEP], List[Dict]]:
        """
        Autonomous mode: The LLM generates SEP/CEP/AEP/FEP from code analysis,
        tests them, learns from failures, and iterates.

        Delegates to the orchestrator's agentic run_with_planner() loop, which
        uses LLM-driven recovery decisions, exploit failure analysis, and fuzzing.

        Returns:
            (final_report, final_sep, final_cep, final_aep, final_fep, iteration_log)
        """
        vuln_path = os.path.join(self.dataset_dir, "vulnerable", test_name)
        patch_path = os.path.join(self.dataset_dir, "injectable", test_name)
        vuln_code, patch_code = self._read_code(test_name)

        if not vuln_code:
            logger.error(f"Cannot read {vuln_path}")
            return (
                VerificationReport(
                    test_name=test_name,
                    sep=SEP(target_id="unknown", image="", working_dir="", dependencies=[]),
                    cep=CEP(success_file="/tmp/pwned"),
                    aep=AEP(tries=[{"input": "", "response": None}]),
                    fep=FEP(tries=[{"input": "", "response": ""}]),
                    verdict=TestVerdict.ERROR,
                    failure_reasons=["File not found"],
                ),
                None, None, None, None, []
            )

        # Auto-generate description from filename if not provided
        if not vuln_description:
            vuln_description = f"Python vulnerability in {test_name}"

        # Create a PlannerAgent and FuzzerAgent with our LLM, then give them
        # to the orchestrator so it can use its full agentic loop (LLM-driven
        # recovery, exploit failure analysis, fuzzing).
        from orchestration.fuzzer_agent import FuzzerAgent
        planner = PlannerAgent(llm_generate_fn=self.llm_generate)
        fuzzer = FuzzerAgent(llm_generate_fn=self.llm_generate)

        # Temporarily equip the orchestrator with planner + fuzzer
        old_planner = self.orchestrator.planner
        old_fuzzer = self.orchestrator.fuzzer
        self.orchestrator.planner = planner
        self.orchestrator.fuzzer = fuzzer

        try:
            # Delegate to the orchestrator's agentic self-correction loop
            report = self.orchestrator.run_with_planner(
                test_name=test_name,
                vuln_code=vuln_code,
                patch_code=patch_code,
                vuln_description=vuln_description,
                vuln_path=vuln_path,
                patch_path=patch_path,
                max_iterations=self.max_fix_attempts,
            )

            # Extract plan components from the report
            sep = report.sep if report else None
            cep = report.cep if report else None
            aep = report.aep if report else None
            fep = report.fep if report else None

            iteration_log = [{
                "iteration": report.iteration if report else 0,
                "verdict": report.verdict.value if report else "ERROR",
                "failure_reasons": report.failure_reasons if report else [],
                "status": "PASS" if (report and report.passed) else "FAIL",
            }]

            return report, sep, cep, aep, fep, iteration_log

        finally:
            # Restore original planner/fuzzer
            self.orchestrator.planner = old_planner
            self.orchestrator.fuzzer = old_fuzzer

    def run_autonomous_suite(
        self,
        filenames: List[str],
        descriptions: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Run the autonomous reasoning loop on a list of test files.
        The LLM generates everything from scratch — no pre-written SEP/AEP.

        Args:
            filenames: list of test filenames (e.g., ["flask_v2.py", "eval_v3.py"])
            descriptions: optional dict mapping filename -> vulnerability description

        Returns:
            Summary dict with results and learning history.
        """
        if descriptions is None:
            descriptions = {}

        results = []
        total_pass = 0
        total_iterations = 0
        total_start = time.time()
        # Accumulate successful plans as "learned" examples
        learned_plans: List[Dict] = []

        logger.info("\n=== VAITP DIAGNOSTIC AGENT: AUTONOMOUS REASONING MODE ===\n")

        for filename in filenames:
            vuln_path = os.path.join(self.dataset_dir, "vulnerable", filename)
            if not os.path.exists(vuln_path):
                logger.warning(f"Skipping {filename}: not found")
                continue

            desc = descriptions.get(filename, f"Vulnerability in {filename}")

            report, sep, cep, aep, fep, iteration_log = self.reason_from_scratch(
                filename, vuln_description=desc
            )

            if report and report.passed:
                total_pass += 1
                # Store successful plan for future learning
                if sep and cep and aep and fep:
                    learned_plans.append({
                        "filename": filename,
                        "sep": {"target_id": sep.target_id, "dependencies": sep.dependencies},
                        "cep": {
                            "strategy": cep.strategy,
                            "success_file": cep.success_file,
                        },
                        "aep": {
                            "first_payload": str(aep.tries[0]["input"])[:100] if aep.tries else "",
                            "num_tries": len(aep.tries),
                        },
                        "fep": {
                            "num_tries": len(fep.tries),
                        },
                        "iterations_needed": report.iteration,
                    })

            total_iterations += len(iteration_log)

            results.append({
                "test_name": filename,
                "verdict": report.verdict.value if report else "ERROR",
                "passed": report.passed if report else False,
                "failure_reasons": report.failure_reasons if report else ["No report"],
                "iterations": len(iteration_log),
                "iteration_log": iteration_log,
            })

        # --- AGENTIC FINAL RETRY PASS ---
        # Re-visit failed tests with accumulated knowledge from successful ones
        failed_results = [(i, r) for i, r in enumerate(results) if not r["passed"]]
        if failed_results and learned_plans:
            logger.info(f"\n{'='*60}")
            logger.info(f"  AGENTIC RETRY: Re-visiting {len(failed_results)} failed test(s) "
                        f"with {len(learned_plans)} learned plan(s)")
            logger.info(f"{'='*60}")

            # Convert learned plans to proven_plans format for the planner
            proven_for_retry = {}
            for lp in learned_plans:
                proven_for_retry[lp["filename"]] = lp

            for result_idx, result_entry in failed_results:
                filename = result_entry["test_name"]
                desc = descriptions.get(filename, f"Retry for {filename}")

                logger.info(f"\n--- RETRY: {filename} (was: {', '.join(result_entry['failure_reasons'])}) ---")

                report, sep, cep, aep, fep, retry_log = self.reason_from_scratch(
                    filename, vuln_description=desc
                )

                total_iterations += len(retry_log)

                if report and report.passed:
                    logger.info(f"  \033[92mRETRY PASS: {filename}\033[0m")
                    total_pass += 1
                    results[result_idx] = {
                        "test_name": filename,
                        "verdict": report.verdict.value,
                        "passed": True,
                        "failure_reasons": [],
                        "iterations": len(retry_log),
                        "iteration_log": retry_log,
                        "retry": True,
                    }
                    # Add to learned plans for subsequent retries
                    if sep and cep and aep and fep:
                        learned_plans.append({
                            "filename": filename,
                            "sep": {"target_id": sep.target_id, "dependencies": sep.dependencies},
                            "cep": {"strategy": cep.strategy, "success_file": cep.success_file},
                            "aep": {"first_payload": str(aep.tries[0].get("input", ""))[:100], "num_tries": len(aep.tries)},
                            "fep": {"num_tries": len(fep.tries)},
                            "iterations_needed": report.iteration,
                        })
                else:
                    logger.warning(f"  \033[91mRETRY FAIL: {filename}\033[0m")

        total_duration = time.time() - total_start

        summary = {
            "mode": "autonomous",
            "total_tests": len(results),
            "passed": total_pass,
            "failed": len(results) - total_pass,
            "total_iterations": total_iterations,
            "duration_seconds": total_duration,
            "learned_plans": learned_plans,
            "results": results,
        }

        self._print_autonomous_summary(summary)
        return summary

    @staticmethod
    def _print_autonomous_summary(summary: Dict[str, Any]):
        """Print summary for autonomous mode."""
        print(f"\n{'='*70}")
        print(f"  AUTONOMOUS REASONING SUMMARY")
        print(f"{'='*70}")
        print(f"  Tests: {summary['total_tests']}  |  "
              f"Passed: {summary['passed']}  |  "
              f"Failed: {summary['failed']}  |  "
              f"Total iterations: {summary['total_iterations']}  |  "
              f"Time: {summary['duration_seconds']:.1f}s")
        if summary['learned_plans']:
            print(f"  Learned plans: {len(summary['learned_plans'])} "
                  f"(avg {sum(p['iterations_needed'] for p in summary['learned_plans'])/len(summary['learned_plans']):.1f} iterations)")
        print(f"{'='*70}")

        for r in summary["results"]:
            color = "\033[92m" if r["passed"] else "\033[91m"
            reset = "\033[0m"
            iters = r["iterations"]
            print(f"  {r['test_name']:<25} | {color}{r['verdict']:<15}{reset} | {iters} iterations")

        print(f"{'='*70}\n")
