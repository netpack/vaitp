#!/usr/bin/env python3
"""
VAITP: End-to-End Test for 1_1.py (Open Redirect — CWE-601)

Runs the FULL Phase 3 framework pipeline for the open redirect test case:
  1. Loads the LLM (deepseek-r1:14b by default)
  2. Calls the PlannerAgent to generate SEP/CEP/AEP/FEP — shows the prompt and plans
  3. Runs the test through Phase3Orchestrator.run_single_test()
  4. If it fails, runs the DiagnosticAgent — shows the diagnostic prompt and fixes
  5. Shows proof of exploitation (success_file created on vuln, blocked on patch)

The vulnerable code creates /tmp/pwned_open_redirect when it processes an external
URL redirect. The patched code rejects external URLs with a 400 response.

Usage:
    python test_1_1_open_redirect.py                          # Full run with deepseek-r1:14b
    python test_1_1_open_redirect.py --model llama-3.1-8b     # Use a different model
    python test_1_1_open_redirect.py --context 8192           # Override context window
    python test_1_1_open_redirect.py --gold                   # Skip LLM, use hand-crafted plans
    python test_1_1_open_redirect.py --max-iterations 5       # More self-correction attempts
    python test_1_1_open_redirect.py --dry-run                # Show plans only, no Docker
"""
import sys
import os
import json
import copy
import time
import logging
import argparse
from typing import Optional, Tuple, Dict, Any, List

from structures import SEP, CEP, AEP, FEP, VerificationReport, TestVerdict, PlannerFeedback
from orchestration.phase3_orchestrator import Phase3Orchestrator
from orchestration.planner_agent import PlannerAgent
from orchestration.diagnostic_agent import (
    DiagnosticAgent, _build_diagnostic_prompt, _extract_diagnostic_json, _apply_aep_fix,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ==========================================
# CONSTANTS
# ==========================================
TEST_NAME = "1_1.py"
VULN_PATH = os.path.join("vaitp_dataset", "vulnerable", TEST_NAME)
PATCH_PATH = os.path.join("vaitp_dataset", "injectable", TEST_NAME)
DATASET_DIR = "vaitp_dataset"
DEFAULT_MODEL = "deepseek-r1:14b"

VULN_DESCRIPTION = (
    "Flask open redirect vulnerability (CWE-601). "
    "The vulnerable version passes user-supplied URL directly to flask.redirect() "
    "without validation, allowing redirection to attacker-controlled external sites. "
    "When an external URL is detected, the vulnerable code creates a side-effect file. "
    "The patched version rejects URLs not starting with '/' with a 400 response. "
    "Strategy: network (Flask app on port 5000)."
)


# ==========================================
# DISPLAY HELPERS
# ==========================================
C = "\033[96m"    # cyan
G = "\033[92m"    # green
Y = "\033[93m"    # yellow
R = "\033[91m"    # red
B = "\033[1m"     # bold
X = "\033[0m"     # reset
SEP_LINE = "=" * 78


def section(title: str, color: str = C):
    print(f"\n{color}{SEP_LINE}")
    print(f"  {title}")
    print(f"{SEP_LINE}{X}\n")


def show_plan(label: str, obj):
    """Pretty-print a dataclass as JSON."""
    if hasattr(obj, '__dict__'):
        d = {k: v for k, v in obj.__dict__.items() if v is not None and v != "" and v != []}
        print(f"  {B}{label}:{X}")
        print(f"  {json.dumps(d, indent=4, default=str)}\n")


def show_prompt(label: str, prompt: str):
    """Print a prompt with line numbers. Full output, never truncated."""
    lines = prompt.split('\n')
    print(f"  {B}{label} ({len(lines)} lines, ~{len(prompt)} chars, ~{len(prompt)//4} tokens est.):{X}")
    print(f"  {'─' * 72}")
    for i, line in enumerate(lines, 1):
        print(f"  {i:4d} │ {line}")
    print(f"  {'─' * 72}\n")


def show_code(label: str, path: str):
    """Print a source file with line numbers."""
    with open(path) as f:
        code = f.read()
    print(f"  {B}{label} ({path}):{X}")
    for i, line in enumerate(code.strip().split('\n'), 1):
        print(f"    {i:3d} │ {line}")
    print()
    return code


def show_report(report: VerificationReport, label: str = "VERIFICATION REPORT (Truth Table)"):
    """Print a formatted verification report."""
    section(label)
    print(f"  Verdict:          {B}{report.verdict.value}{X}")
    print(f"  Failure reasons:  {report.failure_reasons}")
    print(f"  Provision time:   {report.provision_time:.1f}s")
    print(f"  Functional time:  {report.functional_time:.1f}s")
    print(f"  Security time:    {report.security_time:.1f}s")
    print(f"  Total time:       {report.total_time:.1f}s")
    print()

    if report.vuln_functional:
        status = f"{G}PASS{X}" if report.vuln_functional.passed else f"{R}FAIL{X}"
        print(f"  Vuln functional:  {status}")
        print(f"    Output: {report.vuln_functional.output.strip()[:300]}")
        print()
    if report.patch_functional:
        status = f"{G}PASS{X}" if report.patch_functional.passed else f"{R}FAIL{X}"
        print(f"  Patch functional: {status}")
        print(f"    Output: {report.patch_functional.output.strip()[:300]}")
        print()
    if report.vuln_exploit:
        status = f"{Y}EXPLOITED{X}" if report.vuln_exploit.exploited else f"{R}SAFE{X}"
        print(f"  Vuln exploit:     {status}")
        print(f"    Output: {report.vuln_exploit.output.strip()[:300]}")
        print()
    if report.patch_exploit:
        status = f"{R}EXPLOITED{X}" if report.patch_exploit.exploited else f"{G}BLOCKED{X}"
        print(f"  Patch exploit:    {status}")
        print(f"    Output: {report.patch_exploit.output.strip()[:300]}")
        print()



# ==========================================
# GOLD STANDARD PLANS (for --gold mode)
# ==========================================
def get_gold_standard_plans() -> Tuple[SEP, CEP, AEP, FEP]:
    """
    Hand-crafted plans for the open redirect test case.

    Exploit logic:
      - The vulnerable app has /redirecting?url=<target>
      - When url doesn't start with '/', the vuln code creates /tmp/pwned_open_redirect
        as a side-effect (simulating the security impact of processing an external redirect)
      - The patched code rejects external URLs with a 400 before any redirect happens
      - Benign input: /safe → both versions redirect to /safe (response contains "Redirecting")
    """
    sep = SEP(
        target_id="CWE-601",
        image="python:3.9-slim",
        working_dir="/app",
        dependencies=["pip:flask", "curl", "procps"],
        setup_commands=[],
        services=[],
    )

    cep = CEP(
        success_file="/tmp/pwned_open_redirect",
        strategy="network",
        target_url="http://127.0.0.1:5000/redirecting?url=",
        http_method="GET",
        exploit_rationale=(
            "The vulnerable Flask app passes the 'url' query parameter directly to "
            "flask.redirect() without validation. When an external URL is supplied, "
            "the app creates /tmp/pwned_open_redirect as a side-effect before redirecting. "
            "The patched version checks url.startswith('/') and returns 400 for external URLs."
        ),
    )

    aep = AEP(tries=[
        {"input": "https://evil.com", "response": None},
        {"input": "http://attacker.example.org/phish", "response": None},
    ])

    fep = FEP(tries=[
        {"input": "/safe", "response": "Redirecting"},
    ])

    return sep, cep, aep, fep



# ==========================================
# LLM LOADER (reuses test_phase3_diagnostic.py)
# ==========================================
def create_llm_fn(model_key: str, n_ctx_override: int = None):
    """Load a local LLM and return a generate function."""
    from config import REASONING_MODELS, CODER_MODELS, LLM_N_GPU_LAYERS, LLM_N_THREADS, LLM_USE_MMAP

    model_info = REASONING_MODELS.get(model_key) or CODER_MODELS.get(model_key)
    if not model_info:
        available = list(REASONING_MODELS.keys()) + list(CODER_MODELS.keys())
        print(f"  {R}Unknown model '{model_key}'. Available: {available}{X}")
        sys.exit(1)

    model_path = model_info["path"]
    if not os.path.exists(model_path):
        print(f"  {R}Model file not found: {model_path}{X}")
        sys.exit(1)

    n_ctx = n_ctx_override or model_info.get("context_window", 8192)

    logger.info(f"Loading model: {model_key}")
    logger.info(f"  Path: {model_path}")
    logger.info(f"  Context: {n_ctx}, GPU layers: {LLM_N_GPU_LAYERS}, Threads: {LLM_N_THREADS}")

    from llama_cpp import Llama
    t0 = time.time()
    llm = Llama(
        model_path=model_path,
        n_ctx=n_ctx,
        n_gpu_layers=LLM_N_GPU_LAYERS,
        n_threads=LLM_N_THREADS,
        use_mmap=LLM_USE_MMAP,
        verbose=False,
    )
    logger.info(f"  Model loaded in {time.time() - t0:.1f}s")

    def generate(prompt: str, max_tokens: int = 2048) -> str:
        response = llm(
            prompt,
            max_tokens=max_tokens,
            temperature=0.3,
            top_p=0.9,
            stop=["```\n\n", "\n\n\n"],
        )
        if isinstance(response, dict) and "choices" in response:
            return response["choices"][0].get("text", "")
        return str(response)

    return generate



# ==========================================
# PROMPT-CAPTURING WRAPPER
# ==========================================
class PromptCapture:
    """Wraps an LLM generate function to capture all prompts and responses."""

    def __init__(self, llm_fn):
        self._llm_fn = llm_fn
        self.history: List[Dict[str, str]] = []

    def generate(self, prompt: str, max_tokens: int = 2048) -> str:
        t0 = time.time()
        response = self._llm_fn(prompt, max_tokens)
        elapsed = time.time() - t0
        self.history.append({
            "prompt": prompt,
            "response": response,
            "elapsed": elapsed,
            "max_tokens": max_tokens,
        })
        return response

    @property
    def last_prompt(self) -> str:
        return self.history[-1]["prompt"] if self.history else ""

    @property
    def last_response(self) -> str:
        return self.history[-1]["response"] if self.history else ""



# ==========================================
# MAIN
# ==========================================
def main():
    parser = argparse.ArgumentParser(
        description="VAITP: End-to-End Open Redirect Test (1_1.py)"
    )
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"LLM model key (default: {DEFAULT_MODEL})")
    parser.add_argument("--context", type=int, default=None,
                        help="Override model context window size")
    parser.add_argument("--gold", action="store_true",
                        help="Use hand-crafted gold standard plans (skip LLM for planning)")
    parser.add_argument("--max-iterations", type=int, default=3,
                        help="Max self-correction iterations (default: 3)")
    parser.add_argument("--max-diag-attempts", type=int, default=3,
                        help="Max diagnostic fix attempts per failure (default: 3)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show plans only, don't run Docker")
    args = parser.parse_args()

    # ── Step 0: Show source files ──
    section("STEP 0: SOURCE FILES")
    vuln_code = show_code("Vulnerable code", VULN_PATH)
    patch_code = show_code("Patched code", PATCH_PATH)

    # ── Step 1: Load LLM ──
    if not args.gold:
        section("STEP 1: LOADING LLM")
        raw_llm_fn = create_llm_fn(args.model, n_ctx_override=args.context)
        capture = PromptCapture(raw_llm_fn)
        llm_fn = capture.generate
    else:
        section("STEP 1: USING GOLD STANDARD PLANS (--gold, skipping LLM for planning)")
        capture = None
        llm_fn = None

    # ── Step 2: Generate plans ──
    if args.gold:
        section("STEP 2: GOLD STANDARD PLANS")
        sep, cep, aep, fep = get_gold_standard_plans()
    else:
        section("STEP 2: PLANNER AGENT — GENERATING SEP/CEP/AEP/FEP")
        planner = PlannerAgent(llm_generate_fn=llm_fn)
        sep, cep, aep, fep = planner.generate_plan(
            vuln_code=vuln_code,
            patch_code=patch_code,
            vuln_description=VULN_DESCRIPTION,
        )

        if not sep or not cep or not aep or not fep:
            print(f"\n  {R}ERROR: Planner failed to generate plans. Cannot proceed.{X}")
            if capture and capture.history:
                section("PLANNER LLM RAW OUTPUT (for debugging)")
                print(f"  {capture.last_response[:2000]}")
            sys.exit(1)

        # Show the planner prompt
        section("PLANNER PROMPT SENT TO LLM")
        show_prompt("Planner Prompt", capture.last_prompt)

        # Show the raw LLM response
        section("PLANNER LLM RAW RESPONSE")
        print(f"  {B}Response ({len(capture.last_response)} chars, "
              f"{capture.history[-1]['elapsed']:.1f}s):{X}")
        print(f"  {'─' * 72}")
        for line in capture.last_response.strip().split('\n')[:80]:
            print(f"  │ {line}")
        print(f"  {'─' * 72}\n")

    # Show the parsed plans
    section("PARSED EXECUTION PLANS")
    show_plan("SEP (Setup Execution Plan)", sep)
    show_plan("CEP (Common Execution Plan)", cep)
    show_plan("AEP (Attack Execution Plan)", aep)
    show_plan("FEP (Functional Execution Plan)", fep)

    if args.dry_run:
        section("DRY RUN COMPLETE — Skipping Docker execution")
        sys.exit(0)

    # ── Step 3: Run through the framework with self-correction loop ──
    section("STEP 3: RUNNING PHASE 3 ORCHESTRATOR")

    if args.gold:
        # For --gold mode, load the LLM now for diagnostics if needed
        if not llm_fn:
            print(f"  Loading LLM for potential diagnostic analysis...")
            raw_llm_fn = create_llm_fn(args.model, n_ctx_override=args.context)
            capture = PromptCapture(raw_llm_fn)
            llm_fn = capture.generate

    # Use run_with_planner for LLM-generated plans (self-correction loop),
    # or run_single_test for gold standard plans + manual diagnostic loop
    orchestrator = Phase3Orchestrator()

    if args.gold:
        # Gold standard: run once, then diagnostic agent if needed
        print(f"  Running run_single_test with gold standard plans...\n")
        report = orchestrator.run_single_test(
            TEST_NAME, sep, cep, aep, fep, VULN_PATH, PATCH_PATH,
        )
    else:
        # LLM-generated: use the self-correction loop
        print(f"  Running run_with_planner (up to {args.max_iterations} iterations)...\n")
        planner = PlannerAgent(llm_generate_fn=llm_fn)
        orchestrator_with_planner = Phase3Orchestrator(planner=planner)
        report = orchestrator_with_planner.run_with_planner(
            test_name=TEST_NAME,
            vuln_code=vuln_code,
            patch_code=patch_code,
            vuln_description=VULN_DESCRIPTION,
            vuln_path=VULN_PATH,
            patch_path=PATCH_PATH,
            max_iterations=args.max_iterations,
        )

    # Show the report
    show_report(report)

    # ── Step 4: If failed, run diagnostic agent ──
    if not report.passed:
        section("STEP 4: DIAGNOSTIC AGENT — ANALYZING FAILURE")

        diag_agent = DiagnosticAgent(
            llm_generate_fn=llm_fn,
            max_fix_attempts=args.max_diag_attempts,
            dataset_dir=DATASET_DIR,
        )

        # Use the plans from the report (which may have been updated by the planner loop)
        diag_sep = report.sep
        diag_cep = report.cep
        diag_aep = report.aep
        diag_fep = report.fep

        print(f"  Running diagnostic agent (up to {args.max_diag_attempts} fix attempts)...\n")

        # Show the diagnostic prompt that will be built
        vuln_code_diag, patch_code_diag = diag_agent._read_code(TEST_NAME)
        if vuln_code_diag and report.failure_reasons:
            diag_prompt = _build_diagnostic_prompt(
                TEST_NAME, vuln_code_diag, patch_code_diag,
                diag_cep, diag_aep, diag_fep, diag_sep, report,
            )
            section("DIAGNOSTIC PROMPT (first attempt)")
            show_prompt("Diagnostic Prompt", diag_prompt)

        final_report, final_sep, final_cep, final_aep, final_fep, fix_history = \
            diag_agent.diagnose_and_fix(
                TEST_NAME, diag_sep, diag_cep, diag_aep, diag_fep,
            )

        # Show fix history
        if fix_history:
            section("DIAGNOSTIC FIX HISTORY")
            for entry in fix_history:
                print(f"  {B}Attempt {entry.get('attempt', '?')}:{X}")
                if entry.get('error'):
                    print(f"    Error: {entry['error']}")
                else:
                    print(f"    Failure: {entry.get('failure_reasons', [])}")
                    print(f"    Root cause: {entry.get('root_cause', 'N/A')}")
                    print(f"    Fix type: {entry.get('fix_type', 'N/A')}")
                    for fix in entry.get('fixes', []):
                        print(f"    Fix: target={fix.get('target', 'N/A')}, "
                              f"field={fix.get('field', 'N/A')}, "
                              f"new_value={str(fix.get('new_value', ''))[:100]}")
                    if entry.get('note'):
                        print(f"    Note: {entry['note']}")
                print()

        # Show final plans if they changed
        if final_cep != diag_cep or final_aep != diag_aep or final_fep != diag_fep:
            section("PLANS AFTER DIAGNOSTIC FIXES")
            show_plan("CEP (after fix)", final_cep)
            show_plan("AEP (after fix)", final_aep)
            show_plan("FEP (after fix)", final_fep)

        report = final_report
        show_report(report, label="POST-DIAGNOSTIC REPORT")

    else:
        section("STEP 4: DIAGNOSTIC AGENT — NOT NEEDED (test passed)")

    # ── Final summary ──
    section("FINAL SUMMARY")
    if report.passed:
        print(f"  {G}✓ TEST PASSED — Double-Check Methodology verified:{X}")
        print(f"    • Vuln + benign input  → functional (PASS)")
        print(f"    • Patch + benign input → functional (PASS)")
        print(f"    • Vuln + malicious     → exploited (file created)")
        print(f"    • Patch + malicious    → blocked (no file)")
    else:
        print(f"  {R}✗ TEST FAILED — {', '.join(report.failure_reasons)}{X}")

    if capture:
        print(f"\n  LLM calls made: {len(capture.history)}")
        total_llm_time = sum(h["elapsed"] for h in capture.history)
        print(f"  Total LLM time: {total_llm_time:.1f}s")

    print()
    sys.exit(0 if report.passed else 1)


if __name__ == "__main__":
    main()
